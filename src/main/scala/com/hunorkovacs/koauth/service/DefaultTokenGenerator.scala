package com.hunorkovacs.koauth.service

import java.security.SecureRandom
import scala.util.Random

trait TokenGenerator {

  def generateTokenAndSecret: (String, String)

  def generateVerifier: String

  def generateNonce: String
}

object DefaultTokenGenerator extends TokenGenerator {

  private final val LengthToken = 32
  private final val LengthSecret = 32
  private final val LengthVerifier = 16
  private final val LengthNonce = 8
  private val random = new Random(new SecureRandom())

  override def generateTokenAndSecret = (generate(LengthToken), generate(LengthSecret))

  override def generateVerifier = generate(LengthVerifier)

  override def generateNonce = generate(LengthNonce)

  private def generate(length: Int): String = random.alphanumeric.take(length).mkString
}
