package com.hunorkovacs.koauth.service

import java.net.URLDecoder

object OauthExtractor {

  final val UTF8 = "UTF-8"

  def urlDecode(s: String) = URLDecoder.decode(s, UTF8)
}
