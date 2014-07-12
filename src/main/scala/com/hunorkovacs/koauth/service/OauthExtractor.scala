package com.hunorkovacs.koauth.service

import com.hunorkovacs.koauth.domain.{EnhancedRequest, OauthRequest, OauthParams}
import OauthParams._
import java.net.URLDecoder
import scala.concurrent.{ExecutionContext, Future}

object OauthExtractor {

  final val UTF8 = "UTF-8"

  final val AuthorizeRequiredParams = List[String](consumerKeyName, tokenName, usernameName, passwordName)
  final val AccessTokenRequiredParams = List[String](consumerKeyName, tokenName, signatureMethodName,
    signatureName, timestampName, nonceName, versionName, verifierName)
  final val OauthenticateRequiredParams = List[String](consumerKeyName, tokenName, signatureMethodName,
    signatureName, timestampName, nonceName, versionName)

  def enhanceRequest(request: OauthRequest)
                    (implicit ec: ExecutionContext): Future[EnhancedRequest] = {
    val allParamsListF = extractOauthParams(request)
    val allParamsMapF = allParamsListF.map(all => all.toMap)
    for {
      oauthParamsList <- allParamsListF
      oauthParamsMap <- allParamsMapF
    } yield EnhancedRequest(request.method,
      request.urlWithoutParams,
      request.urlParams,
      request.bodyParams,
      oauthParamsList,
      oauthParamsMap)
  }

  def extractOauthParams(request: OauthRequest)
                           (implicit ec: ExecutionContext): Future[List[(String, String)]] = {

    def withoutQuote(s: String) = s.substring(0, s.length - 1)

    Future {
      request.authorizationHeader.stripPrefix("OAuth ")
        .split(",")
        .filter(s => s.contains("=\""))
        .map(param => param.trim)
        .map { keyValue: String =>
          val kv = keyValue.split("=\"")
          val k = urlDecode(kv(0))
          val v = urlDecode(withoutQuote(kv(1)))
          (k, v)
        }.toList
    }
  }

  def urlDecode(s: String) = URLDecoder.decode(s, UTF8)
}
