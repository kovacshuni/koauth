package com.hunorkovacs.koauth.service

import java.net.{URLDecoder, URLEncoder}
import java.nio.charset.StandardCharsets.UTF_8
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import com.hunorkovacs.koauth.domain.OauthParams._

import com.hunorkovacs.koauth.domain._

object Arithmetics {

  private val HmacSha1Algorithm = "HmacSHA1"
  private val FirstSlash = "(?<!/)/(?!/)"

  private val paramSortOrder = (lhs: (String, String), rhs: (String, String)) => {
    val keyOrder = lhs._1.compareTo(rhs._1)
    if (keyOrder < 0) true
    else if (keyOrder > 0) false
    else lhs._2.compareTo(rhs._2) < 0
  }

  private def encodeAndSort(params: List[(String, String)]): List[(String, String)] = {
    params map { p => (urlEncode(p._1), urlEncode(p._2)) } sortWith paramSortOrder
  }

  def urlDecode(s: String) = URLDecoder.decode(s, "UTF-8")

  private val urlEncodePattern = """\+|\*|%7E""".r
  def urlEncode(s: String) = urlEncodePattern.replaceAllIn(URLEncoder.encode(s, "UTF-8"), m => m.group(0) match {
    case "+" => "%20"
    case "*" => "%2A"
    case "%7E" => "~"
  })

  def createAuthorizationHeader(oauthParamsList: List[(String, String)]): String = {
    "OAuth " + (encodeAndSort(oauthParamsList) map { p => p._1 + "=\"" + p._2 + "\"" } mkString ", ")
  }

  def concatItemsForSignature(request: KoauthRequest): String = {
    val method = urlEncode(request.method)
    val url = urlEncode(toLowerCase(request.urlWithoutParams))
    val params =  urlEncode(normalizeRequestParams(request.urlParams, request.oauthParamsList, request.bodyParams))
    List(method, url, params) mkString "&"
  }

  def normalizeRequestParams(urlParams: List[(String, String)],
                             oauthParamsList: List[(String, String)],
                             bodyParams: List[(String, String)]): String = {
    val filtered = oauthParamsList.filterNot(kv => kv._1 == RealmName || kv._1 == SignatureName)
    encodePairSortConcat(urlParams ::: filtered ::: bodyParams)
  }

  def toLowerCase(url: String): String = {
    val parts = url.split(FirstSlash, 2)
    if (parts.length > 1) parts(0).toLowerCase + "/" + parts(1)
    else parts(0).toLowerCase
  }

  def encodePairSortConcat(keyValueList: List[(String, String)]): String = {
    encodeAndSort(keyValueList) map { p =>  p._1 + "=" + p._2 } mkString "&"
  }

  def pairSortConcat(keyValueList: List[(String, String)]): String = {
    keyValueList sortWith paramSortOrder map { p =>  p._1 + "=" + p._2 } mkString "&"
  }

  def createRequestTokenResponse(token: String, secret: String): ResponseOk =
    new ResponseOk(encodePairSortConcat(TokenName -> token
      :: TokenSecretName -> secret
      :: CallbackConfirmedName -> "true"
      :: Nil))

  def createAccesTokenResponse(token: String, secret: String): ResponseOk =
    new ResponseOk(encodePairSortConcat(TokenName -> token :: TokenSecretName -> secret :: Nil))

  def parseRequestTokenResponse(response: String): Either[String, TokenResponse] = {
    val entries = response.split("&").map { p =>
      val pair = p.split("=")
      if (pair.size == 2) (pair(0), pair(1))
      else return Left(response)
    }.toMap
    if (!entries.contains(TokenName) ||
      !entries.contains(TokenSecretName) ||
      entries(CallbackConfirmedName) != "true") Left(response)
    else
      Right(TokenResponse(entries(TokenName), entries(TokenSecretName), entries.get(TokenUserIdName), entries.get(TokenScreenNameName)))
  }

  def parseAccessTokenResponse(response: String): Either[String, TokenResponse] = {
    val entries = response.split("&").map { p =>
      val pair = p.split("=")
      if (pair.size == 2) (pair(0), pair(1))
      else return Left(response)
    }.toMap
    if (!entries.contains(TokenName) || !entries.contains(TokenSecretName)) Left(response)
    else
      Right(TokenResponse(entries(TokenName), entries(TokenSecretName), entries.get(TokenUserIdName), entries.get(TokenScreenNameName)))
  }

  def sign(base: String, consumerSecret: String, tokenSecret: String): String = {
    val key = List(consumerSecret, tokenSecret) map urlEncode mkString "&"
    val secretkeySpec = new SecretKeySpec(key.getBytes(UTF_8), HmacSha1Algorithm)
    val mac = Mac.getInstance(HmacSha1Algorithm)
    mac.init(secretkeySpec)
    val bytesToSign = base.getBytes(UTF_8)
    val digest = mac.doFinal(bytesToSign)
    val digest64 = Base64.getEncoder.encode(digest)
    new String(digest64, UTF_8)
  }
}
