package com.hunorkovacs.koauth.service

import javax.crypto.Mac
import java.nio.charset.Charset
import javax.crypto.spec.SecretKeySpec
import java.util.Base64
import scala.concurrent.{ExecutionContext, Future}
import com.hunorkovacs.koauth.domain.{OauthRequest, OauthParams}
import com.hunorkovacs.koauth.service.OauthCombiner._
import com.hunorkovacs.koauth.domain.exception.OauthUnauthorizedException

object OauthVerifier {

  private final val HmacSha1Algorithm = "HmacSHA1"
  private final val UTF8Charset = Charset.forName(OauthExtractor.UTF8)
  private final val Base64Encoder = Base64.getEncoder

  def verify(requestF: Future[OauthRequest], allOauthParamsF: Future[List[(String, String)]],
             requiredOauthParamsF: Future[OauthParams])(implicit ec: ExecutionContext): Future[Unit] = {
    val consumerSecretF = requiredOauthParamsF.map(p => p.consumerSecret)
    val tokenSecretF = requiredOauthParamsF.map(p => p.tokenSecret)
    val actualSignatureF = requiredOauthParamsF.map(p => p.signature)
    val concatItemsF = concatItemsForSignature(requestF, allOauthParamsF)
    val expectedSignatureF = sign(concatItemsF, consumerSecretF, tokenSecretF)
    for {
      actualSignature <- actualSignatureF
      expectedSignature <- expectedSignatureF
    } yield {
      if (!actualSignature.equals(expectedSignature)) throw new OauthUnauthorizedException("Invalid signature")
    }
  }

  def sign(textToSignF: Future[String], consumerSecretF: Future[String], tokenSecretF: Future[String])
          (implicit ec: ExecutionContext): Future[String] = {
    val secretsF = concatItems(List(consumerSecretF, tokenSecretF))
    val signingKeyF = secretsF.map(secrets => new SecretKeySpec(secrets.getBytes(UTF8Charset), HmacSha1Algorithm))
    val bytesToSignF = textToSignF.map(textToSign => textToSign.getBytes(UTF8Charset))
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
