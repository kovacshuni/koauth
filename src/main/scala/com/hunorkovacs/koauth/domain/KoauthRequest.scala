package com.hunorkovacs.koauth.domain

import java.util.UUID

import com.hunorkovacs.koauth.service.Arithmetics.urlDecode

class KoauthRequest private(val method: String,
                            val urlWithoutParams: String,
                            val urlParams: List[(String, String)],
                            val bodyParams: List[(String, String)],
                            val oauthParamsList: List[(String, String)]) {

  val id = UUID.randomUUID().toString
  val oauthParamsMap: Map[String, String] = oauthParamsList.toMap

  override def toString = {
    "KoauthRequest with id: " + id +
      "; method: " + method +
      "; URL without parameters: " + urlWithoutParams +
      "; URL parameters: " + urlParams +
      "; body parameters" + bodyParams +
      "; Oauth parameters from Authorization header: " + oauthParamsList
  }
}

object KoauthRequest {

  /**
   * Creates a KoauthRequest object specifying the HTTP method, URL without URL parameters separately,
   * the URL parameters, the HTTP body application/x-www-form-urlencoded parameters if any and if that's the Content-Type,
   * and the OAuth parameters.
   *
   * The most explicit creation method.
   *
   * @param method HTTP method e.g. GET
   * @param urlWithoutParams URL without URL parameters e.g. https://api.twitter.com/1.1/statuses/user_timeline.json
   * @param urlParams the parameters in the URL e.g. List(("count", "1"), ("include_rts", "1"))
   * @param bodyParams the parameters in the body if the Content-Type is application/x-www-form-urlencoded
   * @param oauthParamsList the parameters needed specifically for OAuth e.g. List(("oauth_token", "abc"), ...)
   * @return A built up KoauthRequest object
   */
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

  /**
   * Creates a KoauthRequest object specifying the HTTP method, URL without URL parameters separately,
   * the URL parameters, the HTTP body application/x-www-form-urlencoded parameters if any and if that's the Content-Type,
   * and the Authorization header.
   *
   * Is able to parse a string in the format of an Authorization header and extract the Oauth parameters from there.
   *
   * @param method HTTP method e.g. GET
   * @param urlWithoutParams URL without URL parameters e.g. https://api.twitter.com/1.1/statuses/user_timeline.json
   * @param authorizationHeader A string in the format of an OAuth Authorization header.
   * @param urlParams the parameters in the URL e.g. List(("count", "1"), ("include_rts", "1"))
   * @param bodyParams the parameters in the body if the Content-Type is application/x-www-form-urlencoded
   * @return A built up KoauthRequest object
   */
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

  /**
   * Copies a KoauthRequest object. Only the OAuth parameters have to be supplied. Those will be overwritten.
   *
   * @param request the already existing KoauthRequest to be copied
   * @param paramList the parameters needed specifically for OAuth e.g. List(("oauth_token", "abc"), ...)
   * @return A built up KoauthRequest object
   */
  def apply(request: KoauthRequest, paramList: List[(String, String)]) = {
    new KoauthRequest(request.method,
      request.urlWithoutParams,
      request.urlParams,
      request.bodyParams,
      paramList)
  }

  def apply(method: String,
            url: String,
            body: Option[String]) = {
    val urlNoFragment = if (url.contains("#")) url.substring(0, url.indexOf("#"))
    else url
    val urlWithoutParams = if (urlNoFragment.contains("?")) urlNoFragment.substring(0, urlNoFragment.indexOf("?"))
    else urlNoFragment
    val urlParams = extractUrlParams(urlNoFragment.substring(urlNoFragment.indexOf("?") + 1))
    val bodyParams = body match {
      case None => List.empty
      case Some(b) => extractUrlParams(b)
    }
    new KoauthRequest(method,
      urlWithoutParams,
      urlParams,
      bodyParams,
      List.empty)
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

  def extractUrlParams(params: String) =
    params.split("&").toList map { param =>
      if (param.contains("=")) {
        val terms = param.split("=")
        (urlDecode(terms.head), urlDecode(terms.tail.mkString("=")))
      } else (urlDecode(param), "")
    }
}
