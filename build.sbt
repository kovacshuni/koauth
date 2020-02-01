ThisBuild / sonatypeProfileName := "com.hunorkovacs"

ThisBuild / organization := """com.hunorkovacs"""

ThisBuild / version := "2.0.1-SNAPSHOT"

ThisBuild / scalaVersion := "2.12.1"

ThisBuild / crossScalaVersions := Seq("2.11.8")

lazy val root = (project in file("."))
  .aggregate(domain, provider, consumer)

name := """koauth"""

lazy val commonSettings = Seq(
  libraryDependencies ++= {
    val Test = "test"
    val Specs2Version = "3.8.9"
    val Slf4jVersion = "1.7.25"

    Seq(
      "org.slf4j"  % "slf4j-api"    % Slf4jVersion,
      "org.slf4j"  % "slf4j-simple" % Slf4jVersion % Test,
      "org.specs2" %% "specs2-core" % Specs2Version,
      "org.specs2" %% "specs2-mock" % Specs2Version
    )
  }
)

lazy val domain = (project in file("domain"))
  .settings(
    commonSettings,
    name := """domain"""
  )

lazy val provider = (project in file("provider"))
  .dependsOn(domain)
  .settings(
    commonSettings,
    name := """provider"""
  )

lazy val consumer = (project in file("consumer"))
  .dependsOn(domain)
  .settings(
    commonSettings,
    name := """consumer"""
  )

resolvers ++= Seq(
  "Typesafe Releases" at "https://repo.typesafe.com/typesafe/releases/",
  "Sonatype OSS Releases" at "https://oss.sonatype.org/content/repositories/releases"
)

useGpg := true

publishTo := Some("releases" at "https://oss.sonatype.org/service/local/staging/deploy/maven2")

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
    id = "kovacshuni",
    name = "Hunor Kovács",
    email = "kovacshuni@yahoo.com",
    url = url("http://www.hunorkovacs.com")
  )
)
