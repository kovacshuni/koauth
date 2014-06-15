package com.hunorkovacs.koauth.service

import scala.util.Random
import scala.concurrent.{ExecutionContext, Future}

object TokenGenerator {

  private final val Length = 32
  private val random = new Random(System.currentTimeMillis)

  def generateTokenAndSecret(implicit ec: ExecutionContext) =
    (Future(generate), Future(generate))

  def generateVerifier(implicit ec: ExecutionContext) =
    Future(generate)

  private def generate: String = random.alphanumeric.take(Length).mkString
}

