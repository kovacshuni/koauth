sonatypeProfileName := "com.hunorkovacs"

organization := """com.hunorkovacs"""

name := """koauth"""

version := "2.0.0-SNAPSHOT"

scalaVersion := "2.12.1"

crossScalaVersions := Seq("2.10.4", "2.11.8")

resolvers ++= Seq(
  "Typesafe Releases" at "http://repo.typesafe.com/typesafe/releases/",
  "Sonatype OSS Releases" at "https://oss.sonatype.org/content/repositories/releases"
)

libraryDependencies ++= Seq(
  "org.slf4j" % "slf4j-api" % "1.7.25",
  "org.slf4j" % "slf4j-simple" % "1.7.25" % "test",
  "org.specs2" %% "specs2-core" % "3.8.9",
  "org.specs2" %% "specs2-mock" % "3.8.9"
)

useGpg := true

publishTo := Some("releases"  at "https://oss.sonatype.org/service/local/staging/deploy/maven2")

publishMavenStyle := true

licenses := Seq("APL2" -> url("http://www.apache.org/licenses/LICENSE-2.0.txt"))

homepage := Some(url("https://github.com/kovacshuni/koauth"))

scmInfo := Some(
  ScmInfo(
    url("https://github.com/kovacshuni/koauth"),
    "scm:git@github.com:kovacshuni/koauth.git"
  )
)

developers := List(
  Developer(
    id="kovacshuni",
    name="Hunor Kovács",
    email="kovacshuni@yahoo.com",
    url=url("http://www.hunorkovacs.com")
  )
)
