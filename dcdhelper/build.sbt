import Dependencies._

lazy val root = (project in file(".")).
  settings(
    inThisBuild(List(
      organization := "tom.yang",
      scalaVersion := "2.11.6",
      version      := "0.0.1-SNAPSHOT"
    )),
    name := "dcdhelper",
    libraryDependencies += scalaTest % Test,
    mainClass in assembly := Some("tom.yang.main.Main"),
    assemblyJarName in assembly := "dh.jar"
  )

resolvers += Resolver.mavenLocal

libraryDependencies += "org.jnetpcap" % "jnetpcap" % "1.0.0"
