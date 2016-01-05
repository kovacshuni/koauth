import SonatypeKeys._

sonatypeSettings

profileName := "com.hunorkovacs"

organization := """com.hunorkovacs"""

name := """koauth"""

version := "1.2.0"

scalaVersion := "2.11.7"

crossScalaVersions := Seq("2.10.4")

resolvers ++= Seq(
  "Typesafe Releases" at "http://repo.typesafe.com/typesafe/releases/",
  "Sonatype OSS Releases" at "https://oss.sonatype.org/content/repositories/releases"
)

libraryDependencies ++= Seq(
  "org.specs2" %% "specs2" % "2.3.12" % "test",
  "org.slf4j" % "slf4j-api" % "1.7.13",
  "org.slf4j" % "slf4j-simple" % "1.7.13" % "test",
  "commons-codec" % "commons-codec" % "1.10"
)

scalacOptions += "-target:jvm-1.8"

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
      <url>github.com/kovacshuni/koauth</url>
      <tag>1.1.x</tag>
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
