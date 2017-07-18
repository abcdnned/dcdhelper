class Helper{
  import java.io.File
  import java.nio.ByteBuffer
  import java.util.Date
  import org.jnetpcap.Pcap
  import org.jnetpcap.packet.PcapPacket
  import org.jnetpcap.packet.JFlowMap
  import org.jnetpcap.packet.JFlow
  import org.jnetpcap.packet.JFlowKey
  import org.jnetpcap.packet.JPacket
  import org.jnetpcap.nio.JMemory
  import org.jnetpcap.packet.PcapPacketHandler
  import org.jnetpcap.protocol.network.Ip4
  import org.jnetpcap.protocol.tcpip.Tcp
  import org.jnetpcap.packet.format.FormatUtils
  import scala.language.implicitConversions
  import scala.collection.JavaConversions._
  import java.util.TreeMap
  import java.io.PrintWriter
  import java.io.StringWriter
  import scala.collection.mutable.ArrayBuffer


  def parsePayload(packet: JPacket, breflen: Int = 100, payloadAll: Boolean = false) = {
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

  def parseFlow(packet: JPacket): (String, Int, String, Int) = {
    val ip = new Ip4
    val tcp = new Tcp
    if (packet.hasHeader(ip) && packet.hasHeader(tcp)) {
      val sourceIp: String = FormatUtils.ip(ip.source)
      val dstIp: String = FormatUtils.ip(ip.destination)
      return (sourceIp, tcp.source, dstIp, tcp.destination)
    }
    return ("unknown", -1, "unknown", -1)
  }

  trait Target {
    def bref

    def getStackTraceAsString(t: Throwable) = {
        val sw = new StringWriter
        t.printStackTrace(new PrintWriter(sw))
        sw.toString
    }
  }

  var path: String = "/home/tom/gitrepo/dcdhelper/test.pcap"
  //var path: String = "/home/tom/dcdreq/hnnx_1132optz/hnrcu-core-2045-#27.pcap"

  class Flow(val s:Int, val e:Int) extends Target {
    def this(id: Int) {
      this(id, id)
    }

    def this(range: Range) {
      this(range.head, range.last)
    }

    def bref = {
      val errbuf = new java.lang.StringBuilder()
      val pcap = Pcap.openOffline(path, errbuf)
      if (pcap == null)
          println("fail to open pcap file")
      else {
        try {  
          val flows = new ArrayBuffer[Tuple2[JFlowKey, JFlow]]()
          val handler: PcapPacketHandler[String] = new PcapPacketHandler[String]() {
            def nextPacket(packet: PcapPacket, msg: String) {
              val key = packet.getState.getFlowKey
              val iw = flows.indexWhere(t => t._1 == key)
              if (iw == -1) {
                val flow = new JFlow(key)
                flows.append(Tuple2(key, flow))
              } else {
                flows(iw)._2.add(new PcapPacket(packet))
              }
            }
          }
          pcap.loop(-1 , handler, ">");
          println(flows.length)
          var i: Int = 0
          for ((k, v) <- flows) {
            if (i <= e && i >= s) {
              for (p <- v.getAll) {
                parsePayload(p, payloadAll = true)
              }
            }
            i += 1
          }
        } catch {
          case e: Exception => { println("loop failed"); throw e; }
        } finally {  
          pcap.close();  
        }  
      }
    }
  }

  object Flow {
    def apply(n: Int): Flow = {
      return new Flow(n)
    }

    def apply(range: Range): Flow = {
      return new Flow(range)
    }
  }

  class Packet(val s: Int, val e: Int) extends Target {
    def this(id: Int) {
      this(id, id)
    }

    def this(range: Range) {
      this(range.head, range.last)
    }

    def bref {
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
              if (idx >= s && idx <= e) {
                val flow = parseFlow(packet)
                printf("%s pktid %-4d %s:%d -> %s:%d caplen=%-4d \n", msg, idx,
                    flow._1, flow._2, flow._3, flow._4,
                    packet.getCaptureHeader().caplen() // Length actually captured  
                    )  
                parsePayload(packet, payloadAll = true)
              }
            }
          }

          pcap.loop(e + 1, handler, ">");
          pcap.close()
        }
      } catch {
        case _: NumberFormatException => println("loop count must contains only decimal digits")
      }
    }

  }

  object Packet {
    def apply(n: Int): Packet = {
      return new Packet(n)
    }

    def apply(range: Range): Packet = {
      return new Packet(range)
    }
  }

}

import scala.language.postfixOps
val helper = new Helper
import helper._
