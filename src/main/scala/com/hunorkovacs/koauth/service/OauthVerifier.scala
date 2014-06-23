package com.hunorkovacs.koauth.service

import javax.crypto.Mac
import java.nio.charset.Charset
import javax.crypto.spec.SecretKeySpec
import java.util.{TimeZone, Calendar, Base64}
import scala.concurrent.{ExecutionContext, Future}
import com.hunorkovacs.koauth.domain.{OauthParams, EnhancedRequest}
import com.hunorkovacs.koauth.service.OauthCombiner._
import com.hunorkovacs.koauth.domain.OauthParams.{consumerKeyName, timestampName, signatureMethodName, signatureName}
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

  def verify(enhancedRequest: EnhancedRequest,
             tokenSecret: String,
             consumerSecret: String)
            (implicit ec: ExecutionContext): Future[Verification] = {
    val signatureF = verifySignature(enhancedRequest, tokenSecret, consumerSecret)
    val algorithmF = verifyAlgorithm(enhancedRequest)
    val timestampF = verifyTimestamp(enhancedRequest)
    val nonceF = verifyNonce(enhancedRequest, "token123")
    Future.sequence(List(signatureF, algorithmF, timestampF, nonceF)).map { list =>
      list.collectFirst({ case nok: VerificationNok => nok})
        .getOrElse(VerificationOk)
    }
  }

  def verifySignature(enhancedRequest: EnhancedRequest,
                      tokenSecret: String,
                      consumerSecret: String): Future[Verification] = {
    concatItemsForSignature(enhancedRequest) flatMap { signatureBase =>
      sign(signatureBase, consumerSecret, tokenSecret)
    } map { expectedSignature =>
      val actualSignature = enhancedRequest.oauthParamsMap.applyOrElse(signatureName, x => "")
      if (actualSignature.equals(expectedSignature)) VerificationOk
      else VerificationFailed
    }
  }

  def verifyNonce(enhancedRequest: EnhancedRequest, token: String)
                 (implicit persistence: OauthPersistence, ec: ExecutionContext): Future[Verification] = {
    Future {
      val nonce = enhancedRequest.oauthParamsMap.applyOrElse(OauthParams.nonceName, x => "")
      val consumerKey = enhancedRequest.oauthParamsMap.applyOrElse(consumerKeyName, x => "")
      val token = enhancedRequest.oauthParamsMap.applyOrElse(token, x => "")
      (nonce, consumerKey, token)
    } flatMap { t =>
      persistence.nonceExists(t._1, t._2, t._3)
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
