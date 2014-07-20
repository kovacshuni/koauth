package com.hunorkovacs.koauth.service

import scala.util.Random

object Generator {

  private final val LengthToken = 32
  private final val LengthSecret = 32
  private final val LengthVerifier = 16
  private final val LengthNonce = 8
  private val random = new Random(System.currentTimeMillis)

  def generateTokenAndSecret = (generate(LengthToken), generate(LengthSecret))

  def generateVerifier = generate(LengthVerifier)

  def generateNonce = generate(LengthNonce)

  private def generate(length: Int): String = random.alphanumeric.take(length).mkString
}
