import dpkt

__author__ = 'Andrew Ferruzza --------- ' \
             'ID = 111616974'

# Hardcode sender and receiver IP addresses
sender_ip = '130.245.145.12'
receiver_ip = '128.208.2.198'


# Create packet structure
class Packet:

    # Skip ethernet layer and start at IP
    # Reference: https://stackoverflow.com/questions/34009653/convert-bytes-to-int
    # Reference 2: Wireshark to see where the bytes of each variable pertain to

    def __init__(self, timestamp, buffer):
        self.src_IP = str(buffer[26]) + '.' + str(buffer[27]) + '.' + str(buffer[28]) + '.' + str(buffer[29])
        self.dst_IP = str(buffer[30]) + '.' + str(buffer[31]) + '.' + str(buffer[32]) + '.' + str(buffer[33])
        self.src_port = int.from_bytes(buffer[34:36], byteorder='big')
        self.dst_port = int.from_bytes(buffer[36:38], byteorder='big')
        self.seq_number = int.from_bytes(buffer[38:42], byteorder='big')
        self.ack_number = int.from_bytes(buffer[42:46], byteorder='big')

        # Retrieve syn and ack from their positions in the 6 control bits using bitewise
        # Reference: https://wiki.python.org/moin/BitwiseOperators
        # self.test = int.from_bytes(buffer[46:47], byteorder='big')
        flags_bits = int.from_bytes(buffer[47:48], byteorder='big')
        flags_bits = flags_bits >> 1
        self.syn = flags_bits & 1
        flags_bits = flags_bits >> 3
        self.ack = flags_bits & 1
        self.window_size = int.from_bytes(buffer[48:50], byteorder='big')
        self.window_scale = 16384  # multiplier
        self.mss = buffer[56:58]
        self.size = len(buffer)
        self.timestamp = timestamp


# Create connection structure
# A connection contains a source port, dest port, source ip, dest ip, and a list of packets
class Connection:
    src_port = dest_port = src_ip = dest_ip = str

    def __init__(self, s, d, s_ip, d_ip):
        self.src_port = s
        self.dest_port = d
        self.src_ip = s_ip
        self.dest_ip = d_ip
        self.packets = []


# Method to calculate the throughput -- total amount of data sent by the sender
def calculate_throughput(packets):
    start = end = total_bytes = 0
    for pack in packets:
        if pack.src_IP == sender_ip:
            # Starting timestamp
            if start == 0:
                start = pack.timestamp
            else:
                # Sum bytes and keep moving end timestamp along in the loop
                total_bytes += int(pack.size)
                end = pack.timestamp
    time = end - start
    if time != 0:
        throughput = total_bytes / time
    else:
        return None
    return throughput


# Add packets to connection structures for connections.packets list
def check_flow(packets, connections):
    valid = False
    for k in packets:
        for j in range(0, len(connections)):
            if (k.src_port == connections[j].src_port and k.dst_port == connections[j].dest_port) \
                    or (k.src_port == connections[j].dest_port and k.dst_port == connections[j].src_port):
                valid = True
                connections[j].packets.append(k)


# Helper methods for Part B
# Check if the sender = sender_IP and receiver = receiver_IP
def check_SourceDest(packet):
    flag = False
    if packet.src_IP == sender_ip and packet.dst_IP == receiver_ip:
        flag = True
    return flag


# Check if the sender = receiver_IP and receiver = sender_IP
def check_DestSource(packet):
    flag = False
    if packet.dst_IP == sender_ip and packet.src_IP == receiver_ip:
        flag = True
    return flag


# Calculating Congestion
def calculate_congestion_windows(conns, conn_windows):
    conn_windows = []
    initial_pack = 0
    for y in conns.packets:
        if len(conn_windows) < 3:
            if check_SourceDest(y):
                # initial sequence number
                initial_pack = y.seq_number
            # check if there exists a positive sequence - ack from receiver
            elif check_DestSource(y) and initial_pack - y.ack_number > 0:
                congestion = initial_pack - y.ack_number
                conn_windows.append(congestion)
        else:
            break
    return conn_windows


# Part of Question 1
def first_2_transactions(connections):
    count = sender = 0
    for x in connections.packets:
        if x.src_IP == sender_ip:
            # skip initial connection
            if sender == 0:
                sender += 1
            else:
                while count < 2:
                    if x.seq_number is None or x.ack_number is None or x.window_size is None:
                        print("Failed!")
                    else:
                        print("Sequence number: ", x.seq_number, "|Acknowledgement number: ", x.ack_number,
                              "|Window: ", x.window_size * x.window_scale)
                    count += 1


# Methodology adapted from Wireshark's triple duplicate ack logic
# Triple Ack is counted in the third Ack array
# The ack is only added there if it is added in the other 2 ack arrays
def triple_duplicate_ack(conns):
    ack1, ack2, ack3 = [], [], []
    for z in conns.packets:
        # If receiver = sender
        if check_DestSource(z):
            # Second
            if z.ack_number in ack1 and z.ack_number not in ack2:
                ack2.append(z.ack_number)
            # Third (triple)
            elif z.ack_number in ack1 and z.ack_number in ack2 and z.ack_number not in ack3:
                ack3.append(z.ack_number)
            # This is initial
            else:
                ack1.append(z.ack_number)
        else:
            continue
    trip_ack_loss = len(ack3)  # how many unique triple duplicate acks total
    print("Triple Duplicate Ack retransmissions:", trip_ack_loss)
    print("\n")


def main():
    # init values
    tcp_connections = 0
    packet_arr, connections_arr = [], []
    # take input and handle wrong file inputs
    while True:
        try:
            filename = input("Enter file name and include '.pcap' at the end: ")
            file = open(filename, 'rb')
            pcap_file = dpkt.pcap.Reader(file)
        except FileNotFoundError:
            print("File must be a valid .pcap file and input must end with '.pcap'")
        else:
            break

    # Parse pcap
    for ts, bf in pcap_file:
        # eth = dpkt.ethernet.Ethernet(bf)
        packet = Packet(ts, bf)
        packet_arr.append(packet)

    # Parse connections - question 1
    for p in packet_arr:
        # print(p.syn)
        if p.ack == 1 and p.syn == 1:
            tcp_connections += 1
            connection = Connection(p.src_port, p.dst_port, p.src_IP, p.dst_IP)
            connections_arr.append(connection)

    # Append packets to connections' packets lists
    check_flow(packet_arr, connections_arr)

    print('Number of TCP Connections = ', tcp_connections, "\n")
    for i in range(len(connections_arr)):
        print("Connection", i + 1)
        print("----------------")
        print("Source Port: ", connections_arr[i].dest_port, "|", "Source IP", connections_arr[i].dest_ip
              , "|", "Destination Port: ", connections_arr[i].src_port, "|", "Destination IP: ",
              connections_arr[i].src_ip)
        print("Sender throughput (bytes over time): ", calculate_throughput(connections_arr[i].packets))
        print("First two transactions: ")
        if first_2_transactions(connections_arr[i]) is None:
            print("")
        else:
            print(first_2_transactions(connections_arr[i]))
        congestion_windows = []
        congestion_windows = calculate_congestion_windows(connections_arr[i], congestion_windows)
        for j in congestion_windows:
            print("Congestion window: ", j)
        triple_duplicate_ack(connections_arr[i])

    file.close()


if __name__ == '__main__':
    main()
