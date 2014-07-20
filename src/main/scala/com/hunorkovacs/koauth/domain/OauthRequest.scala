package com.hunorkovacs.koauth.domain

import com.hunorkovacs.koauth.service.OauthExtractor.urlDecode

case class Request(method: String,
                   urlWithoutParams: String,
                   urlParams: List[(String, String)],
                   bodyParams: List[(String, String)],
                   oauthParamsList: List[(String, String)],
                   oauthParamsMap: Map[String, String])

object Request {

  def apply(method: String,
            urlWithoutParams: String,
            authorizationHeader: String,
            urlParams: List[(String, String)],
            bodyParams: List[(String, String)]) = {
    val params = extractOauthParams(authorizationHeader)
    new Request(method,
      urlWithoutParams,
      urlParams,
      bodyParams,
      params,
      params.toMap)
  }

  def extractOauthParams(authorizationHeader: String): List[(String, String)] = {
    def withoutQuote(s: String) = s.substring(0, s.length - 1)

    authorizationHeader.stripPrefix("OAuth ")
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

  def apply(request: Request, paramList: List[(String, String)]) = {
    new Request(request.method,
      request.urlWithoutParams,
      request.urlParams,
      request.bodyParams,
      paramList,
      paramList.toMap)
  }
}