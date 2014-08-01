organization := """com.hunorkovacs"""

name := """koauth"""

version := "1.0-SNAPSHOT"

scalaVersion := "2.11.1"

crossScalaVersions := Seq("2.10.3", "2.10.4", "2.11.0")

resolvers ++= Seq(
  "Typesafe Releases" at "http://repo.typesafe.com/typesafe/releases/",
  "Sonatype OSS Releases" at "https://oss.sonatype.org/content/repositories/releases"
)

libraryDependencies ++= Seq(
  "com.typesafe.akka" %% "akka-actor" % "2.3.4",
  "org.specs2" %% "specs2" % "2.3.12" % "test"
)
