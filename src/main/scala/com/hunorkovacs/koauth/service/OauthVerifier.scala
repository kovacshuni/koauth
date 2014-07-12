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

  val MessageInvalidConsumerKey = "Consumer Key does not exist."
  val MessageInvalidToken = "Token with Consumer Key does not exist."
  val MessageInvalidSignature = "Signature does not match."
  val MessageInvalidNonce = "Nonce was already used."
  val MessageInvalidTimestamp = "Timestamp falls outside the tolerated interval."
  val MessageUnsupportedMethod = "Unsupported Signature Method."

  def verifyForRequestToken(enhancedRequest: EnhancedRequest)
            (implicit persistence: OauthPersistence, ec: ExecutionContext): Future[Verification] = {
    Future(enhancedRequest.oauthParamsMap(consumerKeyName))
      .flatMap(persistence.getConsumerSecret)
      .flatMap {
        case None => Future(VerificationFailed(MessageInvalidConsumerKey))
        case Some(consumerSecret) =>
          val signatureF = verifySignature(enhancedRequest, consumerSecret, tokenSecret = "")
          val algorithmF = verifyAlgorithm(enhancedRequest)
          val timestampF = verifyTimestamp(enhancedRequest)
          val nonceF = verifyNonce(enhancedRequest, "")
          Future.sequence(List(signatureF, algorithmF, timestampF, nonceF)) map { list =>
            list.collectFirst({ case nok: VerificationNok => nok })
              .getOrElse(VerificationOk)
          }
      }
  }

  def verifyWithToken(enhancedRequest: EnhancedRequest)
                     (implicit persistence: OauthPersistence, ec: ExecutionContext): Future[Verification] = {
    val tokenF = Future(enhancedRequest.oauthParamsMap(tokenName))
    (for {
      consumerKey <- Future(enhancedRequest.oauthParamsMap(consumerKeyName))
      token <- tokenF
      secret <- persistence.getTokenSecret(consumerKey, token)
    } yield secret) flatMap {
      case None => Future(VerificationFailed(MessageInvalidToken))
      case Some(secret) =>
        tokenF flatMap { token =>
          val signatureF = verifySignature(enhancedRequest, secret, token)
          val algorithmF = verifyAlgorithm(enhancedRequest)
          val timestampF = verifyTimestamp(enhancedRequest)
          val nonceF = verifyNonce(enhancedRequest, "")
          Future.sequence(List(signatureF, algorithmF, timestampF, nonceF)) map { list =>
            list.collectFirst({ case nok: VerificationNok => nok })
              .getOrElse(VerificationOk)
          }
        }
    }
  }

  def verifySignature(enhancedRequest: EnhancedRequest, consumerSecret: String, tokenSecret: String)
                     (implicit ec: ExecutionContext): Future[Verification] = {
    for {
      signatureBase <- concatItemsForSignature(enhancedRequest)
      computedSignature <- sign(signatureBase, consumerSecret, tokenSecret)
    } yield {
      val sentSignature = OauthExtractor.urlDecode(enhancedRequest.oauthParamsMap(signatureName))
      if (sentSignature.equals(computedSignature)) VerificationOk
      else VerificationFailed(MessageInvalidSignature)
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
      if (exists) VerificationFailed(MessageInvalidNonce)
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
        else VerificationFailed(MessageInvalidTimestamp)
      } catch {
        case nfEx: NumberFormatException => VerificationUnsupported("Invalid timestamp format.")
      }
    }
  }

  def verifyAlgorithm(enhancedRequest: EnhancedRequest)
                     (implicit ec: ExecutionContext): Future[Verification] = {
    Future {
      val signatureMethod = enhancedRequest.oauthParamsMap(signatureMethodName)
      if (HmacReadable != signatureMethod) VerificationUnsupported(MessageUnsupportedMethod)
      else VerificationOk
    }
  }

  def sign(base: String, consumerSecret: String, tokenSecret: String)
          (implicit ec: ExecutionContext): Future[String] = {
    Future {
      val key = encodeConcat(List(consumerSecret, tokenSecret))
      val secretkeySpec = new SecretKeySpec(key.getBytes(UTF8Charset), HmacSha1Algorithm)
      val mac = Mac.getInstance(HmacSha1Algorithm)
      mac.init(secretkeySpec)
      val bytesToSign = base.getBytes(UTF8Charset)
      val digest = mac.doFinal(bytesToSign)
      val digest64 = Base64Encoder.encode(digest)
      javax.xml.bind.DatatypeConverter.printHexBinary(digest)
      new String(digest64, UTF8Charset)
    }
  }
}
