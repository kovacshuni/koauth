package com.hunorkovacs.koauth.service

import java.net.{URLDecoder, URLEncoder}
import com.hunorkovacs.koauth.domain.OauthParams._

import scala.concurrent.{ExecutionContext, Future}
import com.hunorkovacs.koauth.domain._

object Arithmetics {

  final val UTF8 = "UTF-8"

  def urlDecode(s: String) = URLDecoder.decode(s, UTF8)

  def urlEncode(s: String) = URLEncoder.encode(s, UTF8)
    .replaceAll("\\+", "%20")
    .replaceAll("\\*", "%2A")
    .replaceAll("%7E", "~")

  def createAuthorizationHeader(oauthParamsList: List[(String, String)]): String = {
    "OAuth " + (oauthParamsList map { p =>
      val k = urlEncode(p._1)
      val v = urlEncode(p._2)
      k + "=\"" + v + "\""
    }).sorted
      .mkString(", ")
  }

  def concatItemsForSignature(request: Request): String = {
    val method = urlEncode(request.method)
    val url = urlEncode(request.urlWithoutParams.toLowerCase)
    val params =  urlEncode(normalizeRequestParams(request.urlParams, request.oauthParamsList, request.bodyParams))
    concat(List(method, url, params))
  }

  def normalizeRequestParams(urlParams: List[(String, String)],
                             oauthParamsList: List[(String, String)],
                             bodyParams: List[(String, String)]): String = {
    val filtered = oauthParamsList.filterNot(kv => kv._1 == realmName || kv._1 == signatureName)
    pairSortConcat(urlParams ::: filtered ::: bodyParams)
  }

  def encodePairSortConcat(keyValueList: List[(String, String)]): String = {
    concat((keyValueList map { keyValue =>
      val (key, value) = keyValue
      urlEncode(key) + "=" + urlEncode(value)
    }).sorted)
  }

  def pairSortConcat(keyValueList: List[(String, String)]): String = {
    concat((keyValueList map { keyValue =>
      val (key, value) = keyValue
      key + "=" + value
    }).sorted)
  }

  def encodeConcat(itemList: List[String]): String = concat(itemList.map(urlEncode))

  def concat(itemList: List[String]): String = itemList.mkString("&")

  def createRequestTokenResponse(token: String, secret: String, callback: String): ResponseOk = {
    val list = List((tokenName, token),
      (tokenSecretName, secret),
      (callbackConfirmedName, callback))
    new ResponseOk(encodePairSortConcat(list))
  }

  def createAuthorizeResponse(token: String, verifier: String): ResponseOk = {
    val list = List((tokenName, token), (verifierName, verifier))
    new ResponseOk(encodePairSortConcat(list))
  }

  def createAccesTokenResponse(token: String, secret: String): ResponseOk = {
    val list = List((tokenName, token), (tokenSecretName, secret))
    new ResponseOk(encodePairSortConcat(list))
  }
}
