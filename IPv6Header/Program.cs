using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PcapDotNet.Base;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Arp;
using PcapDotNet.Packets.Dns;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Gre;
using PcapDotNet.Packets.Http;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.Igmp;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.IpV6;
using PcapDotNet.Packets.Transport;
using System.Threading;
using System.Collections;

namespace IPv6Header
{
    class Program
    {
        static IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine;
        static PacketDevice selectedDevice = allDevices[0];

        static void Main(string[] args)
        {
            if (allDevices.Count == 0)
            {
                Console.WriteLine("No interfaces found! Make sure WinPcap is installed.");
                return;
            }

            // Print the list
            for (int i = 0; i != allDevices.Count; ++i)
            {
                LivePacketDevice device = allDevices[i];
                Console.Write((i + 1) + ". " + device.Name);
                if (device.Description != null)
                    Console.WriteLine(" (" + device.Description + ")");
                else
                    Console.WriteLine(" (Açıklama Yok)");
            }

            int deviceIndex = 0;
            do
            {
                Console.WriteLine("Ağ Aygıtını Seç (1-" + allDevices.Count + "):");
                string deviceIndexString = Console.ReadLine();
                if (!int.TryParse(deviceIndexString, out deviceIndex) ||
                    deviceIndex < 1 || deviceIndex > allDevices.Count)
                {
                    deviceIndex = 0;
                }
            } while (deviceIndex == 0);
            selectedDevice = allDevices[deviceIndex - 1];


            Thread trDinle = new Thread(new ThreadStart(Dinle));
            Thread trIPv6 = new Thread(new ThreadStart(KomutGonder));
            trDinle.Start();
            trIPv6.Start();



        }

        private static void KomutGonder()
        {

            string komut = "";

            while (komut != "ç")
            {
                Console.WriteLine("Gönderilecek Komutu Girin: ");
                komut = Console.ReadLine();
                // Version - Traffic Class - Flow Label - Payload Length - Next Header - Hop Limit - Source Address - Destination Address - Payload 
                IPv6(6, 100, 1523, 6666, 17, 60, "FE80::718C:673D:2ACA:E007", "FE80::718C:673D:2ACA:E007", komut);
                Thread.Sleep(2000);
                // Open the output device
            }
        }

        private static void IPv6(byte Ver, byte TrafficClass, Int16 FlowLabel, Int16 PayloadLength, byte NextHeader, byte HopLimit, string SourceAdd, string DestAdd, string PayloadSTR)
        {
            System.Byte[] Payload = { };
            System.Byte[] SA = { };
            System.Byte[] DA = { };
            System.Byte[] IPv6Packet = { };
            System.Byte Ver_Traffic1 = 0;
            System.Byte Traffic2_Flow1 = 0;
            Int16 FlowLabel2 = 0;

            if (Ver == 6) { Ver = 96; }

            //Ver + Traffic Class(4 biti)
            int k = 0;
            int m = 15;
            int b = 0;
            int c = 65535;
            for (int i = 0; i < 16; i++)
            {

                if (k <= TrafficClass && TrafficClass <= m)
                {

                    Ver_Traffic1 = Convert.ToByte(96 + i);


                }
                k = k + 16;
                m = m + 16;
            }


            for (int j = 0; j < 16; j++)
            {
                if (k <= TrafficClass && TrafficClass <= m)
                {
                    if (b <= FlowLabel && FlowLabel <= c)
                    {
                        Traffic2_Flow1 = Convert.ToByte((j * 16) + j);

                    }

                }

                k = k + 16;
                m = m + 16;
                c = c + 65536;
                b = b + 65536;


            }

            for (int z = 0; z < 16; z++)
            {

                if (b <= FlowLabel && FlowLabel <= c)
                {
                    FlowLabel2 = Convert.ToByte(FlowLabel - (z * 65536));

                }

                c = c + 65536;
                b = b + 65536;

            }

            byte[] intBytesFL = BitConverter.GetBytes(FlowLabel2);
            byte[] FL = intBytesFL;

            byte[] intBytesPL = BitConverter.GetBytes(PayloadLength);
            byte[] PL = intBytesPL;

            Payload = System.Text.Encoding.ASCII.GetBytes(PayloadSTR);
            SA = System.Text.Encoding.ASCII.GetBytes(SourceAdd);
            DA = System.Text.Encoding.ASCII.GetBytes(DestAdd);
            List<byte> bytelistesi1 = new List<byte>();

            bytelistesi1.Add(Ver_Traffic1);
            bytelistesi1.Add(Traffic2_Flow1);
            bytelistesi1.AddRange(FL);
            bytelistesi1.Add(NextHeader);
            bytelistesi1.Add(HopLimit);
            bytelistesi1.AddRange(SA);
            bytelistesi1.AddRange(DA);
            bytelistesi1.AddRange(PL);

            IPv6Packet = bytelistesi1.ToArray(); // listeden tekrar diziye çevir.

            using (PacketCommunicator communicator = selectedDevice.Open(100, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {
                communicator.SendPacket(BuildEthernetPacket(IPv6Packet));
            }

        }

        /// <summary>
        /// This function build an Ethernet with payload packet.
        /// </summary>
        private static Packet BuildEthernetPacket(byte[] yuk)
        {
            EthernetLayer ethernetLayer =
                new EthernetLayer
                {
                    Source = new MacAddress("48:D2:24:1B:AA:9B"),
                    Destination = new MacAddress("48:D2:24:1B:AA:9B"),
                    EtherType = EthernetType.IpV6,
                };

            PayloadLayer payloadLayer =
                new PayloadLayer
                {
                    Data = new Datagram(yuk),
                };

            PacketBuilder builder = new PacketBuilder(ethernetLayer, payloadLayer);

            return builder.Build(DateTime.Now);
        }


        private static void Dinle()
        {

            using (PacketCommunicator communicator =
                selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {
                if (communicator.DataLink.Kind != DataLinkKind.Ethernet)
                {
                    Console.WriteLine("This program works only on Ethernet networks.");
                    return;
                }
                using (BerkeleyPacketFilter filter = communicator.CreateFilter("ip and udp"))
                {
                    // Set the filter
                    communicator.SetFilter(filter);
                }

                // start the capture
                communicator.ReceivePackets(0, PacketHandler);
            }
        }
        private static void PacketHandler(Packet packet)
        {
            // print timestamp and length of the packet
            //Console.WriteLine(packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " length:" + packet.Length);

            IpV6Datagram ip = packet.Ethernet.IpV6;
            UdpDatagram udp = ip.Udp;

            // print ip addresses and udp ports
            if (ip.CurrentDestination.ToString() == "FE80::718C:673D:2ACA:E007" && udp.DestinationPort.ToString() == "6666")
            {
                System.Byte[] bytes = udp.Payload.ToArray<byte>();

                System.Byte[] Payloadbytes = { };
                //------------------------------------------------------
                System.Byte Ver_Traffic1 = bytes[0];
                System.Byte Traffic2_Flow1 = bytes[1];
                System.Byte[] Flow2 = { bytes[2], bytes[3] };
                System.Byte NextHeader = bytes[4];
                System.Byte HopLimit = bytes[5];
                System.Byte[] SA = { bytes[6], bytes[7] };
                System.Byte[] DA = { bytes[8], bytes[9] };
                System.Byte[] Payload = { bytes[10], bytes[11] };
                UInt16 Pay = BitConverter.ToUInt16(Payload, 0);
                UInt16 FlowLabel2 = BitConverter.ToUInt16(Flow2, 0);
                //------------------------------------------------------
                string IPv6Ver = "6";
               // string komuttipi = "";

                // bytes[TokenLength+3] dolgu 1111111. Bu byte'ı atla.
                //-------------------------------------------------------------------------
                List<byte> bytelistesiPayload = new List<byte>();
                //  for (int i = TokenLength + 5; i < bytes.Length ;i++) 
                
                Payloadbytes = bytelistesiPayload.ToArray();
                String Payload1 = Encoding.ASCII.GetString(Payloadbytes);
                //-------------------------------------------------------------------------------------


                Console.WriteLine("########---- KOMUT ALINDI ----#########");
                Console.WriteLine(ip.Source + ":" + udp.SourcePort + " -> " + ip.CurrentDestination + ":" + udp.DestinationPort);
                Console.WriteLine("IP Sürümü: " + IPv6Ver);

                //  Console.WriteLine("Kod: " + Code);
                //Console.WriteLine("Mesaj ID: " + MesajID);
                //Console.WriteLine("Komut Tipi: " + komuttipi);
                Console.WriteLine("Gelen Komut: " + Pay);
                Console.WriteLine("########---- SON ----#########");
                //istek yeni;
                //yeni.ip = ip.Source;
                //yeni.port = udp.SourcePort.ToString();
                //yeni.komuttipi = komuttipi;
                //yeni.komut = komut;
                //Komutlar.Enqueue(yeni);

            }

        }
    }
}
