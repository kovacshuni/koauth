package com.hunorkovacs.koauth.service

import com.hunorkovacs.koauth.domain.{EnhancedRequest, OauthRequest, OauthParams}
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

  def enhanceRequest(request: OauthRequest): Future[EnhancedRequest] = {
    val allParamsListF = extractParams(request)
    val allParamsMapF = allParamsListF.map(all => all.toMap)
    for {
      allParamsList <- allParamsListF
      allParamsMap <- allParamsMapF
    } yield {
      EnhancedRequest(request, allParamsList, allParamsMap)
    }
  }

  def extractParams(request: OauthRequest) = {
    Future(request.authorizationHeader).
      flatMap(extractAllOauthParams)
  }

  def extractAllOauthParams(header: String)(implicit ec: ExecutionContext): Future[List[(String, String)]] = {
    Future {
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
