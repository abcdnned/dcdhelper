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
  import java.nio.file.Files
  import java.nio.file.Path
  import java.nio.file.DirectoryStream

  var path: String = "/home/tom/dcdreq/http/HTTP.pcap"

  def normalOutputPacket(packet: JPacket, title: String, breflen: Int = 100, payloadAll: Boolean = false) = {
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
      if (l != 0) println(title)
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

  val packets = new  ArrayBuffer[Tuple3[Int, String, PcapPacket]]()
  val flows = new ArrayBuffer[Tuple4[Int, JFlowKey, JFlow, ArrayBuffer[Int]]]()
  def load() = {
    try {
      packets.clear()
      flows.clear()
      val errbuf = new java.lang.StringBuilder()
      val pcap = Pcap.openOffline(path, errbuf)
      if (pcap == null)
          println("fail to open pcap file")
      else {
        var idx: Int = 0
        var fc: Int = 0
        val handler: PcapPacketHandler[String] = new PcapPacketHandler[String]() {
          def nextPacket(packet: PcapPacket, msg: String) {
            //manage packet
            val flow = parseFlow(packet)
            val f = "%s pktid %-4d %s:%d -> %s:%d caplen=%-4d".format(msg, idx,
                flow._1, flow._2, flow._3, flow._4,
                packet.getCaptureHeader().caplen() // Length actually captured  
                )  
            packets.append((idx, f, packet))
            //add packet to flows
            val key = packet.getState.getFlowKey
            val iw = flows.indexWhere(t => t._2 == key)
            if (iw == -1) {
              val flow = new JFlow(key)
              val pids = new ArrayBuffer[Int]()
              pids.append(idx)
              flows.append(Tuple4(fc, key, flow, pids))
              flow.add(new PcapPacket(packet))
              fc += 1
            } else {
              flows(iw)._3.add(new PcapPacket(packet))
              flows(iw)._4.append(idx)
            }
            idx += 1
          }
        }
        pcap.loop(-1, handler, ">");
        pcap.close()
      }
    } catch {
      case _: NumberFormatException => println("loop count must contains only decimal digits")
    }
  }
  load()

  trait Target {
    def bref

    def getStackTraceAsString(t: Throwable) = {
        val sw = new StringWriter
        t.printStackTrace(new PrintWriter(sw))
        sw.toString
    }
  }

  def getRecursiveListOfFiles(dir: File): Array[File] = {
      val all = dir.listFiles
      val files = all.filter(_.getName.endsWith(".pcap"))
      files ++ all.filter(_.isDirectory).flatMap(getRecursiveListOfFiles)
  }


  def loadRecent: Unit = {
    val dcdreq: File = new File("/home/tom/dcdreq")
    val md = dcdreq.listFiles.filter(_.isDirectory).maxBy(d => d.lastModified)
    val files = getRecursiveListOfFiles(md)
    var i = 0
    while (i < files.length) {
      println("%d %s".format(i, files(i).getPath))
      i += 1
    }
    val x = scala.io.StdIn.readInt
    println("load recent pcap file " + files(x).getPath)
    path = files(x).getPath
    load()
  }

  class Flow(var s: Int, var e: Int) extends Target {
    def this(id: Int) {
      this(id, id)
    }

    def bref = {
      for ((i, k, f, ps) <- flows.slice(s, e + 1)) {
        println(">>FLOW %d :".format(i))
        for (p <- ps) {
          normalOutputPacket(packets(p)._3, packets(p)._2, payloadAll = true)
        }
      }
    }
  }
  
  object Flow {
    def apply(n: Int): Flow = {
      return new Flow(n)
    }

    def apply(range: Range): Flow = {
      return new Flow(range.head, range.last)
    }
  }

  class Packet(val s: Int, val e: Int) extends Target {
    def this(id: Int) {
      this(id, id)
    }

    def bref {
      for ((i, t, p) <- packets.slice(s, e + 1)) {
        normalOutputPacket(p, t, payloadAll = true)
      }
    }
  }

  object Packet {
    def apply(n: Int): Packet = {
      return new Packet(n)
    }

    def apply(range: Range): Packet = {
      return new Packet(range.head, range.last)
    }
  }

}

import scala.language.postfixOps
val helper = new Helper
import helper._
