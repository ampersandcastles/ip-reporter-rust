use glib::ControlFlow;
use gtk::prelude::*;
use gtk::{
    Application, ApplicationWindow, Button, CellRendererText, FileChooserAction, FileChooserDialog,
    Label, ListStore, ResponseType, TreeView, TreeViewColumn,
};
use pcap::{Capture, Device};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::mpsc::{self};
use std::sync::{Arc, Mutex};
use threadpool::ThreadPool;
use webbrowser;

const DESTINATION_IP: &str = "255.255.255.255";
const SOURCE_PORT: u16 = 14236;
const DESTINATION_PORT: u16 = 14235;

#[derive(Clone)]
struct PacketInfo {
    source_ip: String,
    source_mac: String,
}

fn main() {
    let application = Application::new(Some("com.example.ip_reporter"), Default::default());

    application.connect_activate(|app| {
        let window = ApplicationWindow::new(app);
        window.set_title("IP Reporter");
        window.set_default_size(600, 400);

        let vbox = gtk::Box::new(gtk::Orientation::Vertical, 5);
        let tree_view = TreeView::new();
        let list_store = ListStore::new(&[String::static_type(), String::static_type()]);

        tree_view.set_model(Some(&list_store));
        tree_view.append_column(&create_column("IP Address", 0));
        tree_view.append_column(&create_column("MAC Address", 1));

        let start_button = Button::with_label("Start");
        let export_button = Button::with_label("Export");
        let status_label = Rc::new(RefCell::new(Label::new(Some("Stopped"))));

        vbox.pack_start(&tree_view, true, true, 0);
        vbox.pack_start(&start_button, false, false, 0);
        vbox.pack_start(&export_button, false, false, 0);
        vbox.pack_start(&*status_label.borrow(), false, false, 0);

        window.add(&vbox);
        window.show_all();

        let (tx, rx) = mpsc::channel();
        let listening = Arc::new(Mutex::new(false));
        let packets = Arc::new(Mutex::new(Vec::new()));
        let pool = ThreadPool::new(4);

        {
            let packets = Arc::clone(&packets);
            let list_store = list_store.clone();
            let status_label = Rc::clone(&status_label);
            let listening_main = Arc::clone(&listening);

            start_button.connect_clicked(move |button| {
                let tx = tx.clone();
                let listening = Arc::clone(&listening_main);
                let packets = Arc::clone(&packets);
                let status_label = Rc::clone(&status_label);

                let mut is_listening = listening.lock().unwrap();
                if !*is_listening {
                    *is_listening = true;
                    button.set_label("Stop");
                    status_label.borrow().set_text("Listening...");

                    let listening = Arc::clone(&listening);
                    pool.execute(move || {
                        let device = Device::lookup().unwrap().unwrap();
                        let mut cap = Capture::from_device(device)
                            .unwrap()
                            .promisc(true)
                            .timeout(1000)
                            .open()
                            .unwrap();
                        while *listening.lock().unwrap() {
                            if let Ok(packet) = cap.next_packet() {
                                if let Some(info) = extract_packet_info(packet.data) {
                                    packets.lock().unwrap().push(info.clone());
                                    tx.send(info).unwrap();
                                }
                            }
                        }
                    });
                } else {
                    *is_listening = false;
                    button.set_label("Start");
                    status_label.borrow().set_text("Stopped");
                }
            });

            glib::idle_add_local(move || {
                while let Ok(info) = rx.try_recv() {
                    list_store
                        .insert_with_values(None, &[(0, &info.source_ip), (1, &info.source_mac)]);
                }
                ControlFlow::Continue
            });
        }

        {
            let status_label = Rc::clone(&status_label);
            export_button.connect_clicked(move |_| {
                let dialog = FileChooserDialog::with_buttons(
                    Some("Save File"),
                    Some(&window),
                    FileChooserAction::Save,
                    &[("Cancel", ResponseType::Cancel), ("Save", ResponseType::Ok)],
                );
                if dialog.run() == ResponseType::Ok {
                    if let Some(file_path) = dialog.filename() {
                        let data = packets.lock().unwrap();
                        std::fs::write(
                            file_path,
                            data.iter()
                                .map(|info| {
                                    format!(
                                        "IP Address: {}, MAC Address: {}\n",
                                        info.source_ip, info.source_mac
                                    )
                                })
                                .collect::<String>(),
                        )
                        .unwrap();
                        status_label.borrow().set_text("Data exported.");
                    }
                }
                dialog.close();
            });
        }

        tree_view.connect_row_activated(move |_, path, _| {
            if let Some(iter) = list_store.iter(path) {
                let ip_address: String = list_store.value(&iter, 0).get().unwrap();
                let url = format!("http://root:root@{}", ip_address);

                if webbrowser::open(&url).is_err() {
                    eprintln!("Failed to open URL: {}", url);
                }
            }
        });
    });

    application.run();
}

fn create_column(title: &str, id: i32) -> TreeViewColumn {
    let column = TreeViewColumn::new();
    column.set_title(title);
    column.set_resizable(true);
    column.set_expand(true);

    let cell = CellRendererText::new();
    gtk::prelude::CellLayoutExt::pack_start(&column, &cell, true);
    gtk::prelude::TreeViewColumnExt::add_attribute(&column, &cell, "text", id);

    if title == "IP Address" {
        column.set_fixed_width(50); // Set a fixed width for the IP Address column
    } else {
        column.set_fixed_width(350); // Set a fixed width for other columns
    }

    column
}

fn extract_packet_info(packet: &[u8]) -> Option<PacketInfo> {
    use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::{ipv4::Ipv4Packet, udp::UdpPacket, Packet};
    use std::net::Ipv4Addr;

    let ethernet = EthernetPacket::new(packet)?;
    if ethernet.get_ethertype() == EtherTypes::Ipv4 {
        let ipv4 = Ipv4Packet::new(ethernet.payload())?;
        if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
            let udp = UdpPacket::new(ipv4.payload())?;
            if ipv4.get_destination() == DESTINATION_IP.parse::<Ipv4Addr>().unwrap()
                && udp.get_source() == SOURCE_PORT
                && udp.get_destination() == DESTINATION_PORT
            {
                return Some(PacketInfo {
                    source_ip: ipv4.get_source().to_string(),
                    source_mac: ethernet.get_source().to_string(),
                });
            }
        }
    }
    None
}
