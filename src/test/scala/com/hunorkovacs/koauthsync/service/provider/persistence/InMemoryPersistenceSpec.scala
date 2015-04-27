package com.hunorkovacs.koauthsync.service.provider.persistence

import scala.concurrent.ExecutionContext

class InMemoryPersistenceSpec extends PersistenceSpec(new InMemoryPersistence(ExecutionContext.Implicits.global))
