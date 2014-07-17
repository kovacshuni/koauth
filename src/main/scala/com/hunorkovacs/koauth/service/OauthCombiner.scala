package com.hunorkovacs.koauth.service

import java.net.URLEncoder
import com.hunorkovacs.koauth.domain.OauthParams._

import scala.concurrent.{ExecutionContext, Future}
import com.hunorkovacs.koauth.domain._

object OauthCombiner {

  def urlEncode(s: String) = URLEncoder.encode(s, OauthExtractor.UTF8)
    .replaceAll("\\+", "%20")
    .replaceAll("\\*", "%2A")
    .replaceAll("%7E", "~")

  def createAuthorizationHeader(oauthParamsList: List[(String, String)])
                               (implicit ec: ExecutionContext): Future[String] = {
    Future {
      "OAuth " + (oauthParamsList map { p =>
        val k = urlEncode(p._1)
        val v = urlEncode(p._2)
        k + "=\"" + v + "\""
      }).sorted
        .mkString(", ")
    }
  }

  def concatItemsForSignature(request: EnhancedRequest)
                             (implicit ec: ExecutionContext): Future[String] = {
    for {
      method<- Future(urlEncode(request.method))
      url <- Future(urlEncode(request.urlWithoutParams.toLowerCase))
      params <- normalizeRequestParams(request.urlParams, request.oauthParamsList, request.bodyParams)
        .map(urlEncode)
    } yield concat(List(method, url, params))
  }

  def normalizeRequestParams(urlParams: List[(String, String)],
                             oauthParamsList: List[(String, String)],
                             bodyParams: List[(String, String)])
                            (implicit ec: ExecutionContext): Future[String] = {
    Future{
      val filtered = oauthParamsList.filterNot(kv => kv._1 == realmName || kv._1 == signatureName)
      urlParams ::: filtered ::: bodyParams
    }.flatMap(pairSortConcat)
  }

  def encodePairSortConcat(keyValueList: List[(String, String)])
                        (implicit ec: ExecutionContext): Future[String] = {
    Future {
      concat((keyValueList map { keyValue =>
        val (key, value) = keyValue
        urlEncode(key) + "=" + urlEncode(value)
      }).sorted)
    }
  }

  def pairSortConcat(keyValueList: List[(String, String)])
                      (implicit ec: ExecutionContext): Future[String] = {
    Future {
      concat((keyValueList map { keyValue =>
        val (key, value) = keyValue
        key + "=" + value
      }).sorted)
    }
  }

  def encodeConcat(itemList: List[String]): String = concat(itemList.map(urlEncode))

  def concat(itemList: List[String]): String = itemList.mkString("&")

  def createRequestTokenResponse(token: String, secret: String, callback: String)
                                (implicit ec: ExecutionContext): Future[OauthResponseOk] = {
    Future {
      List((tokenName, token),
        (tokenSecretName, secret),
        (callbackConfirmedName, callback))
    }
      .flatMap(encodePairSortConcat)
      .map(body => new OauthResponseOk(body))
  }

  def createAuthorizeResponse(token: String, verifier: String)
                             (implicit ec: ExecutionContext): Future[OauthResponseOk] =
    encodePairSortConcat(List((tokenName, token), (verifierName, verifier)))
      .map(paramsString => new OauthResponseOk(paramsString))

  def createAccesTokenResponse(token: String, secret: String)
                              (implicit ec: ExecutionContext): Future[OauthResponseOk] =
    encodePairSortConcat(List((tokenName, token), (tokenSecretName, secret)))
      .map(body => new OauthResponseOk(body))
}
