package com.hunorkovacs.koauth.service

import javax.crypto.Mac
import java.nio.charset.Charset
import javax.crypto.spec.SecretKeySpec
import java.util.{TimeZone, Calendar, Base64}
import scala.concurrent.{ExecutionContext, Future}
import com.hunorkovacs.koauth.domain.EnhancedRequest
import com.hunorkovacs.koauth.service.OauthCombiner._
import com.hunorkovacs.koauth.domain.OauthParams._
import com.hunorkovacs.koauth.service.OauthExtractor.UTF8

object OauthVerifier {

  private val HmacSha1Algorithm = "HmacSHA1"
  private val HmacReadable = "HMAC-SHA1"
  private val TimePrecisionMillis = 10 * 60 * 1000
  private val UTF8Charset = Charset.forName(UTF8)
  private val Base64Encoder = Base64.getEncoder
  private val Calendar1 = Calendar.getInstance(TimeZone.getTimeZone("GMT"))

  def verifyForRequestToken(enhancedRequest: EnhancedRequest)
            (implicit persistence: OauthPersistence, ec: ExecutionContext): Future[Verification] = {
    Future(enhancedRequest.oauthParamsMap(consumerKeyName))
      .flatMap(persistence.getConsumerSecret)
      .flatMap {
        case None => Future(VerificationFailed)
        case Some(consumerSecret) => verifySignature(enhancedRequest, consumerSecret, tokenSecret = "")
      }
      .flatMap(v => verifyOtherThanSignature(enhancedRequest, v, token = ""))
  }

  def verifyWithToken(enhancedRequest: EnhancedRequest)
                     (implicit persistence: OauthPersistence, ec: ExecutionContext): Future[Verification] = {
    val tokenF = Future(enhancedRequest.oauthParamsMap(tokenName))
    (for {
      consumerKey <- Future(enhancedRequest.oauthParamsMap(consumerKeyName))
      token <- tokenF
      secret <- persistence.getTokenSecret(consumerKey, token)
    } yield secret) flatMap {
      case None => Future(VerificationFailed)
      case Some(secret) =>
        for {
          token <- tokenF
          signatureVerification <- verifySignature(enhancedRequest, secret, token)
          allVerification <- verifyOtherThanSignature(enhancedRequest, signatureVerification, token)
        } yield allVerification
    }
  }

  def verifyOtherThanSignature(enhancedRequest: EnhancedRequest, signatureVerification: Verification, token: String)
                              (implicit persistence: OauthPersistence, ec: ExecutionContext): Future[Verification] = {
    val algorithmF = verifyAlgorithm(enhancedRequest)
    val timestampF = verifyTimestamp(enhancedRequest)
    val nonceF = verifyNonce(enhancedRequest, token)
    Future.sequence(List(algorithmF, timestampF, nonceF)) map { list =>
      (signatureVerification :: list)
        .collectFirst({ case nok: VerificationNok => nok })
        .getOrElse(VerificationOk)
    }
  }

  def verifySignature(enhancedRequest: EnhancedRequest, consumerSecret: String, tokenSecret: String)
                     (implicit ec: ExecutionContext): Future[Verification] = {
    for {
      signatureBase <- concatItemsForSignature(enhancedRequest)
      expectedSignature <- sign(signatureBase, consumerSecret, tokenSecret)
    } yield {
      val actualSignature = enhancedRequest.oauthParamsMap(signatureName)
      if (actualSignature.equals(expectedSignature)) VerificationOk
      else VerificationFailed
    }
  }

  def verifyNonce(enhancedRequest: EnhancedRequest, token: String)
                 (implicit persistence: OauthPersistence, ec: ExecutionContext): Future[Verification] = {
    Future {
      val nonce = enhancedRequest.oauthParamsMap(nonceName)
      val consumerKey = enhancedRequest.oauthParamsMap(consumerKeyName)
      (nonce, consumerKey)
    } flatMap { t =>
      persistence.nonceExists(t._1, t._2, token)
    } map { exists =>
      if (exists) VerificationFailed
      else VerificationOk
    }
  }

  def verifyTimestamp(enhancedRequest: EnhancedRequest)
                              (implicit ec: ExecutionContext): Future[Verification] = {
    Future {
      val timestamp = enhancedRequest.oauthParamsMap(timestampName)
      try {
        val actualStamp = timestamp.toLong
        val expectedStamp = Calendar1.getTimeInMillis
        if (Math.abs(actualStamp - expectedStamp) <= TimePrecisionMillis) VerificationOk
        else VerificationFailed
      } catch {
        case nfEx: NumberFormatException => VerificationUnsupported
      }
    }
  }

  def verifyAlgorithm(enhancedRequest: EnhancedRequest)
                     (implicit ec: ExecutionContext): Future[Verification] = {
    Future {
      val signatureMethod = enhancedRequest.oauthParamsMap(signatureMethodName)
      if (HmacReadable != signatureMethod) VerificationUnsupported
      else VerificationOk
    }
  }

  def sign(base: String, consumerSecret: String, tokenSecret: String)
                   (implicit ec: ExecutionContext): Future[String] = {
    concat(List(consumerSecret, tokenSecret)) map { secrets =>
      new SecretKeySpec(secrets.getBytes(UTF8Charset), HmacSha1Algorithm)
    } map { signingKey: SecretKeySpec =>
      val bytesToSign = base.getBytes(UTF8Charset)
      val mac = Mac.getInstance(HmacSha1Algorithm)
      mac.init(signingKey)
      val digest = mac.doFinal(bytesToSign)
      val digest64 = Base64Encoder.encode(digest)
      new String(digest64, UTF8Charset)
    }
  }
}
