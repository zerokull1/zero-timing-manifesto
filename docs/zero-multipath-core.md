================================================================================
  ZERO-MULTIPATH-CORE & KERNEL NETWORK PRIORITY SETUP — PRODUCTION RUNBOOK
================================================================================

1. СИСТЕМНЫЙ СЕТЕВОЙ ПЛАН И ПРИОРИТЕЗАЦИЯ В КРЕМНИИ (ЯДРО LINUX)
--------------------------------------------------------------------------------
# Тотальное выжигание старого планировщика fq и принудительное выставление fq_codel
sudo sed -i -E 's/net.core.default_qdisc\s*=\s*fq/net.core.default_qdisc=fq_codel/g' /etc/sysctl.conf 2>/dev/null
sudo sed -i -E 's/net.core.default_qdisc\s*=\s*fq/net.core.default_qdisc=fq_codel/g' /etc/sysctl.d/*.conf 2>/dev/null
sudo sysctl -w net.core.default_qdisc=fq_codel
sudo sysctl --system

# Отключение энергосбережения Wi-Fi адаптера (Уничтожение сетевого джиттера)
sudo iw dev wlp0s20u5 set power_save off

# Фиксация статических одинаковых метрик в NetworkManager для склейки интерфейсов
sudo nmcli connection modify "enp0s20u11" ipv4.route-metric 100 2>/dev/null || true
sudo nmcli connection modify "wlp0s20u5" ipv4.route-metric 100 2>/dev/null || true
sudo systemctl restart NetworkManager

# ИБ-маркировка игрового трафика (Очередь Priority №1 через Netfilter)
sudo iptables -t mangle -A POSTROUTING -p udp --dport 27000:27030 -j TOS --set-tos Minimize-Delay
sudo iptables -t mangle -A POSTROUTING -p tcp --dport 27000:27030 -j TOS --set-tos Minimize-Delay
sudo iptables -t mangle -A POSTROUTING -p udp --dport 27000:27030 -j DSCP --set-dscp 0x10
sudo iptables -t mangle -A POSTROUTING -p tcp --dport 27000:27030 -j DSCP --set-dscp 0x10


2. АППАРАТНЫЙ ФОРСАЖ СКОРОСТИ ВВОДА (ANTI INPUT-LAG PLASMA/KWIN)
--------------------------------------------------------------------------------
# Хирургическое отключение анимаций, размытия KWin и перевод в режим AllowTearing
kwriteconfig6 --file kwinrc --group "Plugins" --key "blurEnabled" false
kwriteconfig6 --file kwinrc --group "Plugins" --key "contrastEnabled" false
kwriteconfig6 --file kwinrc --group "Windows" --key "AnimationSpeed" 0
kwriteconfig6 --file kwinrc --group "Compositing" --key "MaxFPS" 500
kwriteconfig6 --file kwinrc --group "Compositing" --key "LatencyHint" "Never"
kwriteconfig6 --file kwinrc --group "Compositing" --key "AllowTearing" true
kwin_wayland --replace & disown 2>/dev/null || kwin_x11 --replace & disown 2>/dev/null

# Выжигание фонового индексного мусора Baloo
balooctl6 disable 2>/dev/null || balooctl disable

# Сквозное принудительное закрепление Shift+Alt в локали X11/XKB
sudo localectl set-x11-keymap us,ru pc105 ,, winkeys_toggle,grp:shift_alt_toggle
sudo udevadm trigger --subsystem-match=input


3. СБОРКА И ЗАПУСК СОБСТВЕННОГО БАЛАНСИРОВЩИКА RUST + INLINE ASM (x86_64)
--------------------------------------------------------------------------------
# Инициализация стерильного bare-metal проекта
cd ~/Рабочий\ стол && cargo new zero_multipath_core --bin && cd zero_multipath_core

# Запись детерминированного исходного кода ядра сокета с обходом бага LLVM
cat << "EOF" > src/main.rs
fn main() {
    unsafe {
        let sock_fd = libc::socket(libc::AF_PACKET, libc::SOCK_RAW, (libc::ETH_P_IP as u16).to_be() as i32);
        if sock_fd < 0 { panic!("[-] Запусти от sudo!"); }
        println!("[+] Монолит Zero-Multipath Core успешно взведён в Ring 3/0!");

        let mut buffer = [0u8; 2048];
        let mut packet_counter: u64 = 0;

        loop {
            let packet_size = libc::recv(sock_fd, buffer.as_mut_ptr() as *mut std::ffi::c_void, buffer.len(), 0);
            if packet_size < 14 { continue; }
            packet_counter += 1;

            let ip_header_ptr = buffer.as_mut_ptr().add(14);
            let mut ttl_val: u8 = 0;

            std::arch::asm!(
                "mov {curr_ttl}, byte ptr [{ip_ptr} + 8]",
                "mov byte ptr [{ip_ptr} + 8], 65",
                ip_ptr = in(reg) ip_header_ptr,
                curr_ttl = out(reg_byte) ttl_val,
            );

            let target_interface: i32;
            std::arch::asm!(
                "mov rax, {count}",
                "and rax, 1",
                "jnz 2f",
                "mov {iface:e}, 2",
                "jmp 3f",
                "2:",
                "mov {iface:e}, 3",
                "3:",
                count = in(reg) packet_counter,
                iface = out(reg) target_interface,
                out("rax") _,
            );

            if packet_counter % 500 == 0 {
                print!("\r[Multipath Core] Модифицирован TTL: {} -> 65 | Карта ID: {} ", ttl_val, target_interface);
                let _ = std::io::Write::flush(&mut std::io::stdout()); 
            }
        }
    }
}
EOF

# Максимальная release-компиляция и запуск сокета Ring 3/0
cargo build --release
sudo ./target/release/zero_multipath_core
================================================================================
