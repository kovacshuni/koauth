package com.hunorkovacs.koauth.service

import javax.crypto.Mac
import java.nio.charset.Charset
import javax.crypto.spec.SecretKeySpec
import java.util.Base64
import scala.concurrent.{ExecutionContext, Future}
import com.hunorkovacs.koauth.domain.OauthRequest
import com.hunorkovacs.koauth.service.OauthCombiner._
import com.hunorkovacs.koauth.domain.exception.OauthBadRequestException
import com.hunorkovacs.koauth.domain.OauthParams.{signatureMethodName, signatureName}
import com.hunorkovacs.koauth.service.OauthExtractor.UTF8

object OauthVerifier {

  private final val HmacSha1Algorithm = "HmacSHA1"
  private final val HmacReadable = "HMAC-SHA1"
  private final val UTF8Charset = Charset.forName(UTF8)
  private final val Base64Encoder = Base64.getEncoder

  def verify(requestF: Future[OauthRequest],
             allOauthParamsF: Future[List[(String, String)]],
             flatOauthParamsF: Future[Map[String, String]],
             consumerSecretF: Future[String])
            (implicit ec: ExecutionContext): Future[Boolean] = {
    val actualSignatureF = flatOauthParamsF.map(p => p.applyOrElse(signatureName, x => ""))
    val signatureBaseF = concatItemsForSignature(requestF, allOauthParamsF)

    val expectedSignatureF = sign(signatureBaseF, consumerSecretF, Future(""))
    
    val equalityF = for {
      actualSignature <- actualSignatureF
      expectedSignature <- expectedSignatureF
    } yield {
      actualSignature.equals(expectedSignature)
    }

    val correctMethodF = flatOauthParamsF map { p =>
      p.applyOrElse(signatureMethodName, x => "")
    } map { methodName =>
      if (HmacReadable != methodName)
        throw new OauthBadRequestException(s"Signature method '$methodName' is not supported.")
      true
    }

    for {
      equality <- equalityF
      correctMethod <- correctMethodF
    } yield equality && correctMethod
  }

  def sign(baseF: Future[String], consumerSecretF: Future[String], tokenSecretF: Future[String])
          (implicit ec: ExecutionContext): Future[String] = {
    val secretsF = concatItems(List(consumerSecretF, tokenSecretF))
    val signingKeyF = secretsF.map(secrets => new SecretKeySpec(secrets.getBytes(UTF8Charset), HmacSha1Algorithm))
    val bytesToSignF = baseF.map(textToSign => textToSign.getBytes(UTF8Charset))
    val macF = Future(Mac.getInstance(HmacSha1Algorithm))
    val digestBytesFuture = for {
      signingKey <- signingKeyF
      bytesToSign <- bytesToSignF
      mac <- macF
    } yield {
      mac.init(signingKey)
      mac.doFinal(bytesToSign)
    }
    digestBytesFuture.map(Base64Encoder.encode)
      .map(digest64 => new String(digest64, UTF8Charset))
      .map(digestString => URLEncode(digestString))
  }
}
