import tkinter as tk 
from tkinter import scrolledtext
import psutil
import time 
import threading

bg_color = "#0A0A2A"
fg_color = "#FFFFFF"
text_bg_color = "#1A1A4A"
text_fg_color = "#FFFFFF"

def NetInterfaces(root):
    interfaces = psutil.net_if_addrs()
    NetInterfaces_Window = tk.Toplevel(root, bg=bg_color)
    NetInterfaces_Window.title("Network Interfaces")   
    NetInterfaces_Window.geometry("500x400")    
    NetInterfaces_scroll = scrolledtext.ScrolledText(NetInterfaces_Window, wrap=tk.WORD, undo=True, bg=text_bg_color)
    NetInterfaces_scroll.grid(row=3, column=2, padx=10, pady=10)

    for interface, address in interfaces.items():
        NetInterfaces_scroll.config(state=tk.NORMAL) 
        NetInterfaces_scroll.insert(tk.END, f"Intterface : {interface}\n")
        NetInterfaces_scroll.config(state=tk.DISABLED)
        # print(f"Intterface : {interface}")
        for addr in address:
            NetInterfaces_scroll.config(state=tk.NORMAL) 
            NetInterfaces_scroll.insert(tk.END, f"   --Family : {addr.family} | addr = {addr.address}\n")
            NetInterfaces_scroll.config(state=tk.DISABLED)
            # print(f"   --Family : {addr.family} | addr = {addr.address}")

def Netstats(root):
    net_io = psutil.net_io_counters()
    net_stat = psutil.net_io_counters(pernic=True)
    net_statWindow =tk.Toplevel(root,bg=bg_color)
    net_statWindow.title("Network Stats")
    net_statWindow.geometry("500x400")
    net_statWindow_scroll = scrolledtext.ScrolledText(net_statWindow, wrap=tk.WORD, undo=True, bg=text_bg_color)
    net_statWindow_scroll.grid(row=3, column=2, padx=10, pady=10)

    net_statWindow_scroll.config(state=tk.NORMAL)
    net_statWindow_scroll.insert(tk.END, f"Bytes Sent : {net_io.bytes_sent}\n")
    net_statWindow_scroll.insert(tk.END, f"Bytes received : {net_io.bytes_recv}\n")
    net_statWindow_scroll.insert(tk.END, "\n")
    net_statWindow_scroll.config(state=tk.DISABLED)    
    # print(f"Bytes Sent : {net_io.bytes_sent}")
    # print(f"Bytes received : {net_io.bytes_recv}")
    # print("\n")
    for iface,stats in net_stat.items():
        net_statWindow_scroll.config(state=tk.NORMAL)
        net_statWindow_scroll.insert(tk.END, f"{iface} || sent = {stats.bytes_sent} Recv = {stats.bytes_recv}\n")
        net_statWindow_scroll.config(state=tk.DISABLED)
        # print(f"{iface} || sent = {stats.bytes_sent} Recv = {stats.bytes_recv}")

def AtvConInet(root):
    connections = psutil.net_connections(kind="inet")
    AtvConInet_Window = tk.Toplevel(root, bg=bg_color)
    AtvConInet_Window.title("Active Internet Connections")
    AtvConInet_Window.geometry("500x400")
    AtvConInet_scroll = scrolledtext.ScrolledText(AtvConInet_Window, wrap=tk.WORD, undo=True, bg=text_bg_color)
    AtvConInet_scroll.grid(row=3, column=2, padx=10, pady=10)
    for con in connections:
        AtvConInet_scroll.config(state=tk.NORMAL)
        AtvConInet_scroll.insert(tk.END, f"Proto: {con.type} | Local Address {con.laddr} | Remote Address {con.raddr} | status {con.status}\n")
        AtvConInet_scroll.config(state=tk.DISABLED)
        AtvConInet_scroll.yview(tk.END)
        # print(f"Proto: {con.type} | Local Address {con.laddr} | Remote Address {con.raddr} | status {con.status}")

def AtvContcp(root):
    connections = psutil.net_connections(kind="tcp")
    AtvContcp_Window = tk.Toplevel(root, bg=bg_color)
    AtvContcp_Window.title("Active TCP Connections")
    AtvContcp_Window.geometry("500x400")
    AtvContcp_scroll = scrolledtext.ScrolledText(AtvContcp_Window, wrap=tk.WORD, undo=True, bg=text_bg_color)
    AtvContcp_scroll.grid(row=3, column=2, padx=10, pady=10)
    for con in connections:
        AtvContcp_scroll.config(state=tk.NORMAL)
        AtvContcp_scroll.insert(tk.END, f"Proto: {con.type} | Local Address {con.laddr} | Remote Address {con.raddr} | status {con.status}\n")
        AtvContcp_scroll.config(state=tk.DISABLED)
        AtvContcp_scroll.yview(tk.END)
        print(f"Proto: {con.type} | Local Address {con.laddr} | Remote Address {con.raddr} | status {con.status}")

def AtvConudp():
    connections = psutil.net_connections(kind="udp")
    Connection_Window = tk.Toplevel(root, bg=bg_color)
    Connection_Window.title("Active UDP Connections")
    Connection_Window.geometry("500x400")
    Connection_scroll = scrolledtext.ScrolledText(Connection_Window, wrap=tk.WORD, undo=True, bg=text_bg_color)
    Connection_scroll.grid(row=3, column=2, padx=10, pady=10)
    for con in connections:
        Connection_scroll.config(state=tk.NORMAL)
        Connection_scroll.insert(tk.END, f"Proto: {con.type} | Local Address {con.laddr} | Remote Address {con.raddr} | status {con.status}\n")
        Connection_scroll.config(state=tk.DISABLED)
        Connection_scroll.yview(tk.END)
        # print(f"Proto: {con.type} | Local Address {con.laddr} | Remote Address {con.raddr} | status {con.status}")

def NetMonitor():
    old_stats = psutil.net_io_counters()

    while True:
        time.sleep(1)
        new_stats = psutil.net_io_counters()

        sent = new_stats.bytes_sent - old_stats.bytes_sent
        recv = new_stats.bytes_recv - old_stats.bytes_recv

        output = (f"Sent: {sent} bytes/sec | Recevied {recv} bytes/sec")
        Scanner.config(state=tk.NORMAL)
        Scanner.insert(tk.END, output + "\n")
        Scanner.config(state=tk.DISABLED)
        Scanner.yview(tk.END)

        old_stats = new_stats

root = tk.Tk()
root.title("HACKNET_MONITOR")
root.geometry("800x800")

root.configure(bg=bg_color)

main_window = tk.Frame(root, bg=bg_color)
main_window.grid(row=5, column=3, columnspan=2, pady=10, sticky="ew")

Scanner = scrolledtext.ScrolledText(main_window, wrap=tk.WORD, undo=True, bg=text_bg_color)
Scanner.grid(row=1, column=2, padx=10, pady=10)
Scanner.config(state=tk.DISABLED)

NetInterfaces_button = tk.Button(main_window, text="Network Interfaces",background=bg_color, command=lambda: NetInterfaces(root))
NetInterfaces_button.grid(row=2, column=2, padx=10, pady=10)

Netstats_button = tk.Button(main_window, text="Network Stats",background=bg_color, command=lambda: Netstats(root) )
Netstats_button.grid(row=3, column=2, padx=10, pady=10)

AtvConInet_button = tk.Button(main_window, text="Active Internet Connections",background=bg_color, command=lambda: AtvConInet(root))            
AtvConInet_button.grid(row=4, column=2, padx=10, pady=10)

AtvContcp_button = tk.Button(main_window, text="Active TCP Connections",background=bg_color, command=lambda: AtvContcp(root))
AtvContcp_button.grid(row=5, column=2, padx=10, pady=10)

AtvConudp_button = tk.Button(main_window, text="Active UDP Connections",background=bg_color, command=AtvConudp)
AtvConudp_button.grid(row=6, column=2, padx=10, pady=10)

monitor_thread = threading.Thread(target=NetMonitor, daemon=True)
monitor_thread.start()

root.mainloop()