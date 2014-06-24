package com.hunorkovacs.koauth.service

import javax.crypto.Mac
import java.nio.charset.Charset
import javax.crypto.spec.SecretKeySpec
import java.util.{TimeZone, Calendar, Base64}
import scala.concurrent.{ExecutionContext, Future}
import com.hunorkovacs.koauth.domain.{OauthParams, EnhancedRequest}
import com.hunorkovacs.koauth.service.OauthCombiner._
import com.hunorkovacs.koauth.domain.OauthParams._
import com.hunorkovacs.koauth.service.OauthExtractor.UTF8

trait Verification
case object VerificationOk extends Verification
trait VerificationNok extends Verification
case object VerificationUnsupported extends VerificationNok
case object VerificationFailed extends VerificationNok

object OauthVerifier {

  private val HmacSha1Algorithm = "HmacSHA1"
  private val HmacReadable = "HMAC-SHA1"
  private val TimePrecisionMillis = 10 * 60 * 1000
  private val UTF8Charset = Charset.forName(UTF8)
  private val Base64Encoder = Base64.getEncoder
  private val Calendar1 = Calendar.getInstance(TimeZone.getTimeZone("GMT"))

  def verifyForRequestToken(enhancedRequest: EnhancedRequest)
            (implicit persistence: OauthPersistence, ec: ExecutionContext): Future[Verification] = {
    val signatureF = verifySignature(enhancedRequest, "")
    val algorithmF = verifyAlgorithm(enhancedRequest)
    val timestampF = verifyTimestamp(enhancedRequest)
    val nonceF = verifyNonce(enhancedRequest, "")
    Future.sequence(List(signatureF, algorithmF, timestampF, nonceF)) map { list =>
      list.collectFirst({ case nok: VerificationNok => nok })
        .getOrElse(VerificationOk)
    }
  }

  def verifyForAccessToken(enhancedRequest: EnhancedRequest)
                           (implicit persistence: OauthPersistence, ec: ExecutionContext): Future[Verification] = {
    val signatureF = verifySignature(enhancedRequest, enhancedRequest.oauthParamsMap(tokenName))
    val algorithmF = verifyAlgorithm(enhancedRequest)
    val timestampF = verifyTimestamp(enhancedRequest)
    val nonceF = verifyNonce(enhancedRequest, enhancedRequest.oauthParamsMap(tokenName))
    Future.sequence(List(signatureF, algorithmF, timestampF, nonceF)) map { list =>
      list.collectFirst({ case nok: VerificationNok => nok })
        .getOrElse(VerificationOk)
    }
  }

  def verifySignature(enhancedRequest: EnhancedRequest, tokenSecret: String)
                     (implicit persistence: OauthPersistence, ec: ExecutionContext): Future[Verification] = {
    val consumerSecretF = Future(enhancedRequest.oauthParamsMap.applyOrElse(consumerKeyName, x => ""))
      .flatMap(consumerKey => persistence.getConsumerSecret(consumerKey))
    val signatureBaseF = concatItemsForSignature(enhancedRequest)
    for {
      consumerSecret <- consumerSecretF
      signatureBase <- signatureBaseF
      expectedSignature <- sign(signatureBase, consumerSecret, tokenSecret)
    } yield {
      val actualSignature = enhancedRequest.oauthParamsMap.applyOrElse(signatureName, x => "")
      if (actualSignature.equals(expectedSignature)) VerificationOk
      else VerificationFailed
    }
  }

  def verifyNonce(enhancedRequest: EnhancedRequest, token: String)
                 (implicit persistence: OauthPersistence, ec: ExecutionContext): Future[Verification] = {
    Future {
      val nonce = enhancedRequest.oauthParamsMap.applyOrElse(nonceName, x => "")
      val consumerKey = enhancedRequest.oauthParamsMap.applyOrElse(consumerKeyName, x => "")
      (nonce, consumerKey)
    } flatMap { t =>
      persistence.nonceExists(t._1, t._2, token)
    } map { exists =>
      if (exists) VerificationOk
      else VerificationFailed
    }
  }

  def verifyTimestamp(enhancedRequest: EnhancedRequest)
                     (implicit ec: ExecutionContext): Future[Verification] = {
    Future {
      val timestamp = enhancedRequest.oauthParamsMap.applyOrElse(timestampName, x => "")
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

  def verifyAlgorithm(enhancedRequest: EnhancedRequest): Future[Verification] = {
    Future {
      val signatureMethod = enhancedRequest.oauthParamsMap.applyOrElse(signatureMethodName, x => "")
      if (HmacReadable != signatureMethod) VerificationUnsupported
      else VerificationOk
    }
  }

  def sign(base: String, consumerSecret: String, tokenSecret: String)
          (implicit ec: ExecutionContext): Future[String] = {
    concatItems(List(consumerSecret, tokenSecret)) map { secrets =>
      new SecretKeySpec(secrets.getBytes(UTF8Charset), HmacSha1Algorithm)
    } map { signingKey: SecretKeySpec =>
      val bytesToSign = base.getBytes(UTF8Charset)
      val mac = Mac.getInstance(HmacSha1Algorithm)
      mac.init(signingKey)
      val digest = mac.doFinal(bytesToSign)
      val digest64 = Base64Encoder.encode(digest)
      val digestString = new String(digest64, UTF8Charset)
      URLEncode(digestString)
    }
  }
}
