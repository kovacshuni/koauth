package com.hunorkovacs.koauth.domain

import com.hunorkovacs.koauth.service.Arithmetics.urlDecode

class KoauthRequest private(val method: String,
                            val urlWithoutParams: String,
                            val urlParams: List[(String, String)],
                            val bodyParams: List[(String, String)],
                            val oauthParamsList: List[(String, String)]) {

  val oauthParamsMap: Map[String, String] = oauthParamsList.toMap
}

object KoauthRequest {

  def apply(method: String,
            urlWithoutParams: String,
            urlParams: List[(String, String)],
            bodyParams: List[(String, String)],
            oauthParamsList: List[(String, String)]) = {
    new KoauthRequest(method,
      urlWithoutParams,
      urlParams,
      bodyParams,
      oauthParamsList)
  }

  def apply(method: String,
            urlWithoutParams: String,
            authorizationHeader: Option[String],
            urlParams: List[(String, String)],
            bodyParams: List[(String, String)]) = {
    val params = extractOauthParams(authorizationHeader)
    new KoauthRequest(method,
      urlWithoutParams,
      urlParams,
      bodyParams,
      params)
  }

  def apply(request: KoauthRequest, paramList: List[(String, String)]) = {
    new KoauthRequest(request.method,
      request.urlWithoutParams,
      request.urlParams,
      request.bodyParams,
      paramList)
  }

  def extractOauthParams(authorizationHeader: Option[String]): List[(String, String)] = {
    def withoutQuote(s: String) = s.substring(0, s.length - 1)

    authorizationHeader.getOrElse("")
      .stripPrefix("OAuth ")
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
