package com.hunorkovacs.koauth.service

import scala.util.Random
import scala.concurrent.{ExecutionContext, Future}

object TokenGenerator {
  def generateTokenAndSecret(implicit ec: ExecutionContext): (Future[String], Future[String]) =
    (Future(Random.nextString(20)), Future(Random.nextString(20)))

  def generateVerifier(implicit ec: ExecutionContext): Future[String] = Future(Random.nextString(20))
}
