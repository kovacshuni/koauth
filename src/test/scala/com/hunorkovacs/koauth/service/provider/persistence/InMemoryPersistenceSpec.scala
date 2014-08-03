package com.hunorkovacs.koauth.service.provider.persistence

import scala.concurrent.ExecutionContext

class InMemoryPersistenceSpec extends PersistenceSpec(new InMemoryPersistence()(ExecutionContext.Implicits.global))
