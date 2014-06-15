package com.hunorkovacs.koauth.service

import com.hunorkovacs.koauth.domain.OauthParams
import OauthParams._
import java.net.URLDecoder
import scala.concurrent.{ExecutionContext, Future}
import com.hunorkovacs.koauth.domain.exception.OauthBadRequestException

object OauthExtractor {

  final val UTF8 = "UTF-8"

  final val RequestTokenRequiredParams = List[String](consumerKeyName, signatureMethodName, signatureName,
    timestampName, nonceName, versionName, callbackName)
  final val AuthorizeRequiredParams = List[String](consumerKeyName, tokenName, usernameName, passwordName)
  final val AccessTokenRequiredParams = List[String](consumerKeyName, tokenName, signatureMethodName,
    signatureName, timestampName, nonceName, versionName, verifierName)
  final val OauthenticateRequiredParams = List[String](consumerKeyName, tokenName, signatureMethodName,
    signatureName, timestampName, nonceName, versionName)

  def extractAllOauthParams(headerF: Future[String])(implicit ec: ExecutionContext): Future[List[(String, String)]] = {
    headerF map { header =>
      val array = header.stripPrefix("OAuth ")
        .replaceAll("\"", "")
        .split(",") map { param =>
        URLDecode(param)
      } map { keyValue: String =>
        val kv = keyValue.split("=")
        val k = kv(0)
        val v = if (kv.size == 2) kv(1) else ""
        (k, v)
      }
      array.toList
    }
  }

  def URLDecode(s: String) = URLDecoder.decode(s, UTF8)
}
