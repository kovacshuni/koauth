package com.hunorkovacs.koauth.service

import com.hunorkovacs.koauth.domain.{EnhancedRequest, OauthRequest, OauthParams}
import OauthParams._
import java.net.URLDecoder
import scala.concurrent.{ExecutionContext, Future}

object OauthExtractor {

  final val UTF8 = "UTF-8"

  final val RequestTokenRequiredParams = List[String](consumerKeyName, signatureMethodName, signatureName,
    timestampName, nonceName, versionName, callbackName)
  final val AuthorizeRequiredParams = List[String](consumerKeyName, tokenName, usernameName, passwordName)
  final val AccessTokenRequiredParams = List[String](consumerKeyName, tokenName, signatureMethodName,
    signatureName, timestampName, nonceName, versionName, verifierName)
  final val OauthenticateRequiredParams = List[String](consumerKeyName, tokenName, signatureMethodName,
    signatureName, timestampName, nonceName, versionName)

  def enhanceRequest(request: OauthRequest)
                    (implicit ec: ExecutionContext): Future[EnhancedRequest] = {
    val allParamsListF = extractAllOauthParams(request)
    val allParamsMapF = allParamsListF.map(all => all.toMap)
    for {
      allParamsList <- allParamsListF
      allParamsMap <- allParamsMapF
    } yield EnhancedRequest(request, allParamsList, allParamsMap)
  }

  def extractAllOauthParams(request: OauthRequest)
                           (implicit ec: ExecutionContext): Future[List[(String, String)]] = {
    Future {
      request.authorizationHeader.stripPrefix("OAuth ")
        .replaceAll("\"", "")
        .split(",")
        .map(param => urlDecode(param))
        .map { keyValue: String =>
        val kv = keyValue.split("=")
        val k = kv(0)
        val v = if (kv.size == 2) kv(1) else ""
        (k, v)
      }.toList
    }
  }

  def urlDecode(s: String) = URLDecoder.decode(s, UTF8)
}
