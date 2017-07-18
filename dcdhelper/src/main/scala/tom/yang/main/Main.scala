package tom.yang.main

import java.io.File
import java.nio.ByteBuffer
import java.util.Date
import javax.xml.bind.DatatypeConverter
import org.jnetpcap.Pcap
import org.jnetpcap.packet.PcapPacket
import org.jnetpcap.packet.PcapPacketHandler

object Main extends App {

    def parse(packet: PcapPacket) = {
      val bytes: Array[Byte] = new Array[Byte](packet.getCaptureHeader.caplen)
      val buff: ByteBuffer = ByteBuffer.wrap(bytes)
      packet.transferTo(buff)
      println(DatatypeConverter.printHexBinary(bytes))
    }

    var idx: Int = 0

    val path = System.getProperty("java.library.path")
    try {
      if (args.length > 1) {
          val errbuf = new java.lang.StringBuilder()
          val path = args(0)
          val cnt = args(1).toInt
          println(path)
          val pcap = Pcap.openOffline(path, errbuf)
          if (pcap == null)
              println("fail to open pcap file")
          else {
              val handler: PcapPacketHandler[String] = new PcapPacketHandler[String]() {
                  def nextPacket(packet: PcapPacket, msg: String) {
                      idx += 1
                      printf("%s pktid %d Received at %s caplen=%-4d len=%-4d \n", msg, idx,
                              new Date(packet.getCaptureHeader().timestampInMillis()),   
                              packet.getCaptureHeader().caplen(), // Length actually captured  
                              packet.getCaptureHeader().wirelen() // Original length  
                              )  
                      parse(packet)
                  }
              }

              pcap.loop(cnt, handler, ">");
              pcap.close()
          }
      } else {
          println("please input enough arguments : pcap file path and loop count")
      }
    } catch {
      case _: NumberFormatException => println("loop count must contains only decimal digits")
    }
    
}
