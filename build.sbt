import SonatypeKeys._

sonatypeSettings

profileName := "com.hunorkovacs"

organization := """com.hunorkovacs"""

name := """koauth-sync"""

version := "1.0.0"

scalaVersion := "2.11.1"

crossScalaVersions := Seq("2.10.4")

scalacOptions in ThisBuild ++= Seq("-unchecked", "-deprecation")

resolvers ++= Seq(
  "Typesafe Releases" at "http://repo.typesafe.com/typesafe/releases/",
  "Sonatype OSS Releases" at "https://oss.sonatype.org/content/repositories/releases"
)

libraryDependencies ++= Seq(
  "com.typesafe.akka" %% "akka-actor" % "2.3.4",
  "org.specs2" %% "specs2" % "2.3.12",
  "org.slf4j" % "slf4j-api" % "1.7.7"
)

pomExtra := {
  <url>https://github.com/kovacshuni/koauth</url>
    <licenses>
      <license>
        <name>Apache 2</name>
        <url>http://www.apache.org/licenses/LICENSE-2.0.txt</url>
      </license>
    </licenses>
    <scm>
      <connection>scm:git:github.com/kovacshuni/koauth</connection>
      <developerConnection>scm:git@github.com:kovacshuni/koauth.git</developerConnection>
      <tag>sync</tag>
      <url>https://github.com/kovacshuni/koauth/tree/sync</url>
    </scm>
    <developers>
      <developer>
        <id>kovacshuni</id>
        <name>Hunor Kovács</name>
        <url>www.hunorkovacs.com</url>
      </developer>
    </developers>
}

publishTo := Some("releases"  at "https://oss.sonatype.org/service/local/staging/deploy/maven2")

publishMavenStyle := true

publishArtifact in Test := true
