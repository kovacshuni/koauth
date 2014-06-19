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

import scala.util.{Try, Failure}

object OauthVerifier {

  private val HmacSha1Algorithm = "HmacSHA1"
  private val HmacReadable = "HMAC-SHA1"
  private val UTF8Charset = Charset.forName(UTF8)
  private val Base64Encoder = Base64.getEncoder

  trait Verification
  case object VerificationPositive extends Verification
  case class VerificationNegative(message: String) extends Verification

  def verify(request: OauthRequest,
             allParamsList: List[(String, String)],
             allParamsMap: Map[String, String],
             tokenSecret: String,
             consumerSecret: String)
            (implicit ec: ExecutionContext): Future[Verification] = {
    val equalityF: Future[Verification] = concatItemsForSignature(request, allParamsList) flatMap { signatureBase =>
      sign(signatureBase, consumerSecret, tokenSecret)
    } map { expectedSignature =>
      val actualSignature = allParamsMap.applyOrElse(signatureName, x => "")
      if(actualSignature.equals(expectedSignature)) VerificationPositive
      else VerificationNegative("ana are mere")
    }

    val correctMethodF: Future[Verification] = Future {
      val signatureMethod = allParamsMap.applyOrElse(signatureMethodName, x => "")
      if (HmacReadable != signatureMethod) VerificationNegative(s"Signature method '$signatureMethod' is not supported.")
      else VerificationPositive
      //        new OauthBadRequestException(s"Signature method '$signatureMethod' is not supported."))
      // throw new OauthBadRequestException(s"Signature method '$signatureMethod' is not supported.")
    }

    for {
      equality <- equalityF
      correctMethod <- correctMethodF
    } yield {
      equality match {
        case VerificationPositive => {
          correctMethod match {
            case VerificationPositive => VerificationPositive
            case els => els
          }
        }
        case els => els
      }
    }

//    }List(equality, correctMethod).collectFirst{
//      case _: VerificationNegative => true
//      case _ => false
//    }
  }

  def k = {
    verify().recover {
      ex: OauthBadRequestException => BadRequest(ex.message)
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
      val digest64 = mac.doFinal(bytesToSign)
      val digestString = new String(digest64, UTF8Charset)
      URLEncode(digestString)
    }
  }
}
