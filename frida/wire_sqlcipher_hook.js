'use strict';

import Java from 'frida-java-bridge';

function bytesToHex(bytes) {
  if (bytes === null || bytes === undefined) {
    return null;
  }

  const out = [];
  for (let i = 0; i < bytes.length; i++) {
    out.push(('0' + (bytes[i] & 0xff).toString(16)).slice(-2));
  }
  return out.join('');
}

function bytesPreview(bytes, limit) {
  if (bytes === null || bytes === undefined) {
    return null;
  }

  const end = Math.min(bytes.length, limit);
  let out = '';
  for (let i = 0; i < end; i++) {
    const value = bytes[i] & 0xff;
    out += value >= 0x20 && value <= 0x7e ? String.fromCharCode(value) : '.';
  }
  return out;
}

function emit(event, fields) {
  const payload = Object.assign({ event: event }, fields);
  send(payload);
}

function shortBacktrace() {
  try {
    return Java.backtrace({ limit: 8 }).frames
      .map(function (frame) {
        return frame.className + '.' + frame.methodName;
      })
      .join(' <- ');
  } catch (err) {
    return String(err);
  }
}

function reportKey(where, database, password) {
  emit('sqlcipher-key', {
    where: where,
    database: database === null || database === undefined ? null : String(database),
    key_len: password === null || password === undefined ? 0 : password.length,
    key_hex: bytesToHex(password),
    key_preview: bytesPreview(password, 32),
    caller: shortBacktrace()
  });
}

function reportStringKey(where, database, password) {
  emit('sqlcipher-key', {
    where: where,
    database: database === null || database === undefined ? null : String(database),
    key_len: password === null || password === undefined ? 0 : String(password).length,
    key_string: password === null || password === undefined ? null : String(password),
    caller: shortBacktrace()
  });
}

function hookKeyOverloads(klass, methodName, databaseIndex, keyIndex, where) {
  let hooked = 0;
  klass[methodName].overloads.forEach(function (overload) {
    const argumentTypes = overload.argumentTypes.map(function (type) {
      return type.className;
    });
    const keyType = argumentTypes[keyIndex];
    if (keyType !== '[B' && keyType !== 'java.lang.String') {
      return;
    }

    overload.implementation = function () {
      const args = Array.prototype.slice.call(arguments);
      const label = keyType === '[B' ? 'byte[]' : 'String';
      if (keyType === '[B') {
        reportKey(where + '(' + label + ')', args[databaseIndex], args[keyIndex]);
      } else {
        reportStringKey(where + '(' + label + ')', args[databaseIndex], args[keyIndex]);
      }
      return overload.apply(this, args);
    };
    hooked++;
  });
  return hooked;
}

function hookHelperDatabaseMethod(SQLiteOpenHelper, methodName) {
  let hooked = 0;
  SQLiteOpenHelper[methodName].overloads.forEach(function (overload) {
    if (overload.argumentTypes.length !== 0) {
      return;
    }

    overload.implementation = function () {
      reportKey(
        'SQLiteOpenHelper.' + methodName + '()',
        this.mName.value,
        this.mPassword.value
      );
      return overload.call(this);
    };
    hooked++;
  });
  return hooked;
}

function hookMessages() {
  const Cursor = Java.use('net.zetetic.database.AbstractWindowedCursor');
  const getString = Cursor.getString.overload('int');
  const seen = new Set();

  getString.implementation = function (column) {
    const value = getString.call(this, column);
    if (value === null || String(this.getColumnName(column)) !== 'text') {
      return value;
    }

    const text = String(value);
    const read = function (name) {
      const index = this.getColumnIndex(name);
      if (index < 0) {
        return null;
      }
      const field = getString.call(this, index);
      return field === null ? null : String(field);
    }.bind(this);
    const messageId = read('id');
    const conversationId = read('conversationId');
    const key = conversationId + ':' + messageId + ':' + text;

    if (text.length > 0 && !seen.has(key)) {
      seen.add(key);
      emit('wire-message', {
        conversation_id: conversationId,
        message_id: messageId,
        date: read('date'),
        sender: read('senderName'),
        text: text
      });
    }
    return value;
  };
  return 1;
}

Java.perform(function () {
  const hookCounts = {
    helper_constructor: 0,
    helper_database: 0,
    open_database: 0,
    open_or_create_database: 0,
    connection_open: 0,
    native_key: 0,
    message_cursor: 0
  };

  try {
    const SQLiteOpenHelper = Java.use('net.zetetic.database.sqlcipher.SQLiteOpenHelper');
    hookCounts.helper_constructor = hookKeyOverloads(
      SQLiteOpenHelper,
      '$init',
      1,
      2,
      'SQLiteOpenHelper.<init>'
    );
    hookCounts.helper_database += hookHelperDatabaseMethod(
      SQLiteOpenHelper,
      'getReadableDatabase'
    );
    hookCounts.helper_database += hookHelperDatabaseMethod(
      SQLiteOpenHelper,
      'getWritableDatabase'
    );
  } catch (err) {
    emit('hook-error', {
      target: 'net.zetetic.database.sqlcipher.SQLiteOpenHelper',
      error: String(err)
    });
  }

  try {
    const SQLiteDatabase = Java.use('net.zetetic.database.sqlcipher.SQLiteDatabase');
    hookCounts.open_database = hookKeyOverloads(
      SQLiteDatabase,
      'openDatabase',
      0,
      1,
      'SQLiteDatabase.openDatabase'
    );
    hookCounts.open_or_create_database = hookKeyOverloads(
      SQLiteDatabase,
      'openOrCreateDatabase',
      0,
      1,
      'SQLiteDatabase.openOrCreateDatabase'
    );
  } catch (err) {
    emit('hook-error', {
      target: 'net.zetetic.database.sqlcipher.SQLiteDatabase',
      error: String(err)
    });
  }

  try {
    const SQLiteConnection = Java.use('net.zetetic.database.sqlcipher.SQLiteConnection');
    SQLiteConnection.open.overloads.forEach(function (overload) {
      if (overload.argumentTypes.length !== 0) {
        return;
      }

      overload.implementation = function () {
        const configuration = this.mConfiguration.value;
        reportKey(
          'SQLiteConnection.open()',
          configuration.path.value,
          configuration.password.value
        );
        return overload.call(this);
      };
      hookCounts.connection_open++;
    });

    const nativeKey = SQLiteConnection.nativeKey.overload('long', '[B');
    nativeKey.implementation = function (connectionPtr, password) {
      reportKey('SQLiteConnection.nativeKey()', null, password);
      return nativeKey.call(this, connectionPtr, password);
    };
    hookCounts.native_key++;
  } catch (err) {
    emit('hook-error', {
      target: 'net.zetetic.database.sqlcipher.SQLiteConnection',
      error: String(err)
    });
  }

  try {
    hookCounts.message_cursor = hookMessages();
  } catch (err) {
    emit('hook-error', {
      target: 'net.zetetic.database.AbstractWindowedCursor.getString',
      error: String(err)
    });
  }

  emit('loaded', {
    package: String(Java.use('android.app.ActivityThread').currentPackageName()),
    note: 'Wire SQLCipher hooks installed',
    hooks: hookCounts
  });
});
