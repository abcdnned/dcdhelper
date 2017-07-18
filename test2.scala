class Helper{
  import java.io.File
  import java.nio.ByteBuffer
  import java.util.Date
  import org.jnetpcap.Pcap
  import org.jnetpcap.packet.PcapPacket
  import org.jnetpcap.packet.PcapPacketHandler
  import org.jnetpcap.protocol.network.Ip4
  import org.jnetpcap.protocol.tcpip.Tcp
  import org.jnetpcap.packet.format.FormatUtils
  import scala.language.implicitConversions


  class Target(val cnt: Int, var off: Int = 0) {
    def packet = this
    def offset(o: Int) = { 
      off = o
      this
    }

    def parsePayload(packet: PcapPacket, breflen: Int, payloadAll: Boolean) = {
      val ip = new Ip4
      val tcp = new Tcp
      if (packet.hasHeader(ip) && packet.hasHeader(tcp)) {
        val s = if (ip.length > 46) 14 + ip.hlen * 4 + tcp.hlen * 4 else 60
        val caplen = packet.getCaptureHeader.caplen
        val showlen = if (caplen > s) caplen - s else 0
        var l: Int = if (payloadAll) showlen else breflen min showlen
        val bytes: Array[Byte] = new Array[Byte](l)
        val buff: ByteBuffer = ByteBuffer wrap bytes
        packet.transferTo(buff, s, l)
        println(FormatUtils.hexdump(bytes))
      }
    }

    def parseFlow(packet: PcapPacket): (String, Int, String, Int) = {
      val ip = new Ip4
      val tcp = new Tcp
      if (packet.hasHeader(ip) && packet.hasHeader(tcp)) {
        val sourceIp: String = FormatUtils.ip(ip.source)
        val dstIp: String = FormatUtils.ip(ip.destination)
        return (sourceIp, tcp.source, dstIp, tcp.destination)
      }
      return ("unknown", -1, "unknown", -1)
    }

    var path: String = "/home/tom/gitrepo/dcdhelper/test.pcap"

    def bref: Unit = {
      bref()
    }

    def bref(len: Int = 100, payload: Boolean = true, payloadAll: Boolean = false): Unit = {
      try {
        val errbuf = new java.lang.StringBuilder()
        val pcap = Pcap.openOffline(path, errbuf)
        if (pcap == null)
            println("fail to open pcap file")
        else {
          var idx: Int = 0
          val handler: PcapPacketHandler[String] = new PcapPacketHandler[String]() {
            def nextPacket(packet: PcapPacket, msg: String) {
              idx += 1
              if (idx > off) {
                val flow = parseFlow(packet)
                printf("%s pktid %-4d %s:%d -> %s:%d caplen=%-4d \n", msg, idx,
                    flow._1, flow._2, flow._3, flow._4,
                    packet.getCaptureHeader().caplen() // Length actually captured  
                    )  
                if (payload)
                  parsePayload(packet, len, payloadAll)
              }
            }
          }

          pcap.loop(off + cnt, handler, ">");
          pcap.close()
        }
      } catch {
        case _: NumberFormatException => println("loop count must contains only decimal digits")
      }
    }
  }

  implicit def int2Target(n: Int) = new Target(n)
}

val helper = new Helper
import helper._
