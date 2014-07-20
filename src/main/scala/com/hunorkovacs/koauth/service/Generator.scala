package com.hunorkovacs.koauth.service

import scala.util.Random
import scala.concurrent.{ExecutionContext, Future}

object Generator {

  private final val Length = 32
  private val random = new Random(System.currentTimeMillis)

  def generateTokenAndSecret(implicit ec: ExecutionContext) = Future((generate, generate))

  def generateVerifier(implicit ec: ExecutionContext) = Future(generate)

  def generateNonce = generate

  private def generate: String = random.alphanumeric.take(Length).mkString
}

