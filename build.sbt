name := """koauth"""

version := "1.0-SNAPSHOT"

scalaVersion := "2.11.1"

resolvers ++= Seq(
  "Typesafe Releases" at "http://repo.typesafe.com/typesafe/releases/",
  "Sonatype OSS Releases" at "https://oss.sonatype.org/content/repositories/releases"
)

libraryDependencies ++= Seq(
  "com.typesafe.akka" % "akka-actor_2.10" % "2.3.3",
  "org.scala-lang.modules" %% "scala-async" % "0.9.1",
  "org.specs2" %% "specs2" % "2.3.12" % "test"
)
