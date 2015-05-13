package com.hunorkovacs.koauth.service

import java.net.{URLDecoder, URLEncoder}
import java.nio.charset.Charset
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import com.hunorkovacs.koauth.domain.OauthParams._

import com.hunorkovacs.koauth.domain._

object Arithmetics {

  final val UTF8 = "UTF-8"
  private val HmacSha1Algorithm = "HmacSHA1"
  private val UTF8Charset = Charset.forName(UTF8)
  private val Base64Encoder = Base64.getEncoder
  private val FirstSlash = "(?<!/)/(?!/)"

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

  def concatItemsForSignature(request: KoauthRequest): String = {
    val method = urlEncode(request.method)
    val url = urlEncode(toLowerCase(request.urlWithoutParams))
    val params =  urlEncode(normalizeRequestParams(request.urlParams, request.oauthParamsList, request.bodyParams))
    concat(List(method, url, params))
  }

  def normalizeRequestParams(urlParams: List[(String, String)],
                             oauthParamsList: List[(String, String)],
                             bodyParams: List[(String, String)]): String = {
    val filtered = oauthParamsList.filterNot(kv => kv._1 == RealmName || kv._1 == SignatureName)
    pairSortConcat(urlParams ::: filtered ::: bodyParams)
  }

  def toLowerCase(url: String): String = {
    val parts = url.split(FirstSlash, 2)
    if (parts.length > 1) parts(0).toLowerCase + "/" + parts(1)
    else parts(0).toLowerCase
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
    val list = List((TokenName, token),
      (TokenSecretName, secret),
      (CallbackConfirmedName, callback))
    new ResponseOk(encodePairSortConcat(list))
  }

  def createAccesTokenResponse(token: String, secret: String): ResponseOk = {
    val list = List((TokenName, token), (TokenSecretName, secret))
    new ResponseOk(encodePairSortConcat(list))
  }

  def parseRequestTokenResponse(response: String) = {
    val entries = response.split("&").map { p =>
      val pair = p.split("=")
      (pair(0), pair(1))
    }.toMap
    if (!entries.contains(TokenName) ||
      !entries.contains(TokenSecretName) ||
      entries(CallbackConfirmedName) != "true") Left(response)
    else Right(TokenResponse(entries(TokenName), entries(TokenSecretName)))
  }

  def parseAccessTokenResponse(response: String) = {
    val entries = response.split("&").map { p =>
      val pair = p.split("=")
      (pair(0), pair(1))
    }.toMap
    if (!entries.contains(TokenName) || !entries.contains(TokenSecretName)) Left(response)
    else Right(TokenResponse(entries(TokenName), entries(TokenSecretName)))
  }

  def sign(base: String, consumerSecret: String, tokenSecret: String): String = {
    val key = encodeConcat(List(consumerSecret, tokenSecret))
    val secretkeySpec = new SecretKeySpec(key.getBytes(UTF8Charset), HmacSha1Algorithm)
    val mac = Mac.getInstance(HmacSha1Algorithm)
    mac.init(secretkeySpec)
    val bytesToSign = base.getBytes(UTF8Charset)
    val digest = mac.doFinal(bytesToSign)
    val digest64 = Base64Encoder.encode(digest)
    new String(digest64, UTF8Charset)
  }
}
