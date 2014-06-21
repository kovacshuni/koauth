package com.hunorkovacs.koauth.service

import javax.crypto.Mac
import java.nio.charset.Charset
import javax.crypto.spec.SecretKeySpec
import java.util.Base64
import scala.concurrent.{ExecutionContext, Future}
import com.hunorkovacs.koauth.domain.{EnhancedRequest, OauthRequest}
import com.hunorkovacs.koauth.service.OauthCombiner._
import com.hunorkovacs.koauth.domain.OauthParams.{signatureMethodName, signatureName}
import com.hunorkovacs.koauth.service.OauthExtractor.UTF8

trait Verification
case object VerificationOk extends Verification
trait VerificationNok extends Verification
case object VerificationUnsupported extends VerificationNok
case object VerificationFailed extends VerificationNok

object OauthVerifier {

  private val HmacSha1Algorithm = "HmacSHA1"
  private val HmacReadable = "HMAC-SHA1"
  private val UTF8Charset = Charset.forName(UTF8)
  private val Base64Encoder = Base64.getEncoder

  def verify(enhancedRequest: EnhancedRequest,
             tokenSecret: String,
             consumerSecret: String)
            (implicit ec: ExecutionContext): Future[Verification] = {
    val equalityF: Future[Verification] = concatItemsForSignature(enhancedRequest) flatMap { signatureBase =>
      sign(signatureBase, consumerSecret, tokenSecret)
    } map { expectedSignature =>
      val actualSignature = enhancedRequest.oauthParamsMap.applyOrElse(signatureName, x => "")
      if (actualSignature.equals(expectedSignature)) VerificationOk
      else VerificationFailed
    }

    val correctMethodF: Future[Verification] = Future {
      val signatureMethod = enhancedRequest.oauthParamsMap.applyOrElse(signatureMethodName, x => "")
      if (HmacReadable != signatureMethod) VerificationUnsupported
      else VerificationOk
    }

    for {
      equality <- equalityF
      correctMethod <- correctMethodF
    } yield {
      List(equality, correctMethod)
        .collectFirst({ case nok: VerificationNok => nok})
        .getOrElse(VerificationOk)
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
