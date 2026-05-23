// coverage:ignore-file
// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'api.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

T _$identity<T>(T value) => value;

final _privateConstructorUsedError = UnsupportedError(
    'It seems like you constructed your class using `MyClass._()`. This constructor is only meant to be used by freezed and you are not supposed to need it nor use it.\nPlease check the documentation here for more information: https://github.com/rrousselGit/freezed#adding-getters-and-methods-to-our-models');

/// @nodoc
mixin _$ConnectionState {
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() connected,
    required TResult Function() disconnected,
    required TResult Function() connecting,
    required TResult Function(LinuxLinkErrorDto field0) error,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? connected,
    TResult? Function()? disconnected,
    TResult? Function()? connecting,
    TResult? Function(LinuxLinkErrorDto field0)? error,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? connected,
    TResult Function()? disconnected,
    TResult Function()? connecting,
    TResult Function(LinuxLinkErrorDto field0)? error,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(ConnectionState_Connected value) connected,
    required TResult Function(ConnectionState_Disconnected value) disconnected,
    required TResult Function(ConnectionState_Connecting value) connecting,
    required TResult Function(ConnectionState_Error value) error,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(ConnectionState_Connected value)? connected,
    TResult? Function(ConnectionState_Disconnected value)? disconnected,
    TResult? Function(ConnectionState_Connecting value)? connecting,
    TResult? Function(ConnectionState_Error value)? error,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(ConnectionState_Connected value)? connected,
    TResult Function(ConnectionState_Disconnected value)? disconnected,
    TResult Function(ConnectionState_Connecting value)? connecting,
    TResult Function(ConnectionState_Error value)? error,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $ConnectionStateCopyWith<$Res> {
  factory $ConnectionStateCopyWith(
          ConnectionState value, $Res Function(ConnectionState) then) =
      _$ConnectionStateCopyWithImpl<$Res, ConnectionState>;
}

/// @nodoc
class _$ConnectionStateCopyWithImpl<$Res, $Val extends ConnectionState>
    implements $ConnectionStateCopyWith<$Res> {
  _$ConnectionStateCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of ConnectionState
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc
abstract class _$$ConnectionState_ConnectedImplCopyWith<$Res> {
  factory _$$ConnectionState_ConnectedImplCopyWith(
          _$ConnectionState_ConnectedImpl value,
          $Res Function(_$ConnectionState_ConnectedImpl) then) =
      __$$ConnectionState_ConnectedImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$ConnectionState_ConnectedImplCopyWithImpl<$Res>
    extends _$ConnectionStateCopyWithImpl<$Res, _$ConnectionState_ConnectedImpl>
    implements _$$ConnectionState_ConnectedImplCopyWith<$Res> {
  __$$ConnectionState_ConnectedImplCopyWithImpl(
      _$ConnectionState_ConnectedImpl _value,
      $Res Function(_$ConnectionState_ConnectedImpl) _then)
      : super(_value, _then);

  /// Create a copy of ConnectionState
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$ConnectionState_ConnectedImpl extends ConnectionState_Connected {
  const _$ConnectionState_ConnectedImpl() : super._();

  @override
  String toString() {
    return 'ConnectionState.connected()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$ConnectionState_ConnectedImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() connected,
    required TResult Function() disconnected,
    required TResult Function() connecting,
    required TResult Function(LinuxLinkErrorDto field0) error,
  }) {
    return connected();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? connected,
    TResult? Function()? disconnected,
    TResult? Function()? connecting,
    TResult? Function(LinuxLinkErrorDto field0)? error,
  }) {
    return connected?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? connected,
    TResult Function()? disconnected,
    TResult Function()? connecting,
    TResult Function(LinuxLinkErrorDto field0)? error,
    required TResult orElse(),
  }) {
    if (connected != null) {
      return connected();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(ConnectionState_Connected value) connected,
    required TResult Function(ConnectionState_Disconnected value) disconnected,
    required TResult Function(ConnectionState_Connecting value) connecting,
    required TResult Function(ConnectionState_Error value) error,
  }) {
    return connected(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(ConnectionState_Connected value)? connected,
    TResult? Function(ConnectionState_Disconnected value)? disconnected,
    TResult? Function(ConnectionState_Connecting value)? connecting,
    TResult? Function(ConnectionState_Error value)? error,
  }) {
    return connected?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(ConnectionState_Connected value)? connected,
    TResult Function(ConnectionState_Disconnected value)? disconnected,
    TResult Function(ConnectionState_Connecting value)? connecting,
    TResult Function(ConnectionState_Error value)? error,
    required TResult orElse(),
  }) {
    if (connected != null) {
      return connected(this);
    }
    return orElse();
  }
}

abstract class ConnectionState_Connected extends ConnectionState {
  const factory ConnectionState_Connected() = _$ConnectionState_ConnectedImpl;
  const ConnectionState_Connected._() : super._();
}

/// @nodoc
abstract class _$$ConnectionState_DisconnectedImplCopyWith<$Res> {
  factory _$$ConnectionState_DisconnectedImplCopyWith(
          _$ConnectionState_DisconnectedImpl value,
          $Res Function(_$ConnectionState_DisconnectedImpl) then) =
      __$$ConnectionState_DisconnectedImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$ConnectionState_DisconnectedImplCopyWithImpl<$Res>
    extends _$ConnectionStateCopyWithImpl<$Res,
        _$ConnectionState_DisconnectedImpl>
    implements _$$ConnectionState_DisconnectedImplCopyWith<$Res> {
  __$$ConnectionState_DisconnectedImplCopyWithImpl(
      _$ConnectionState_DisconnectedImpl _value,
      $Res Function(_$ConnectionState_DisconnectedImpl) _then)
      : super(_value, _then);

  /// Create a copy of ConnectionState
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$ConnectionState_DisconnectedImpl extends ConnectionState_Disconnected {
  const _$ConnectionState_DisconnectedImpl() : super._();

  @override
  String toString() {
    return 'ConnectionState.disconnected()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$ConnectionState_DisconnectedImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() connected,
    required TResult Function() disconnected,
    required TResult Function() connecting,
    required TResult Function(LinuxLinkErrorDto field0) error,
  }) {
    return disconnected();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? connected,
    TResult? Function()? disconnected,
    TResult? Function()? connecting,
    TResult? Function(LinuxLinkErrorDto field0)? error,
  }) {
    return disconnected?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? connected,
    TResult Function()? disconnected,
    TResult Function()? connecting,
    TResult Function(LinuxLinkErrorDto field0)? error,
    required TResult orElse(),
  }) {
    if (disconnected != null) {
      return disconnected();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(ConnectionState_Connected value) connected,
    required TResult Function(ConnectionState_Disconnected value) disconnected,
    required TResult Function(ConnectionState_Connecting value) connecting,
    required TResult Function(ConnectionState_Error value) error,
  }) {
    return disconnected(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(ConnectionState_Connected value)? connected,
    TResult? Function(ConnectionState_Disconnected value)? disconnected,
    TResult? Function(ConnectionState_Connecting value)? connecting,
    TResult? Function(ConnectionState_Error value)? error,
  }) {
    return disconnected?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(ConnectionState_Connected value)? connected,
    TResult Function(ConnectionState_Disconnected value)? disconnected,
    TResult Function(ConnectionState_Connecting value)? connecting,
    TResult Function(ConnectionState_Error value)? error,
    required TResult orElse(),
  }) {
    if (disconnected != null) {
      return disconnected(this);
    }
    return orElse();
  }
}

abstract class ConnectionState_Disconnected extends ConnectionState {
  const factory ConnectionState_Disconnected() =
      _$ConnectionState_DisconnectedImpl;
  const ConnectionState_Disconnected._() : super._();
}

/// @nodoc
abstract class _$$ConnectionState_ConnectingImplCopyWith<$Res> {
  factory _$$ConnectionState_ConnectingImplCopyWith(
          _$ConnectionState_ConnectingImpl value,
          $Res Function(_$ConnectionState_ConnectingImpl) then) =
      __$$ConnectionState_ConnectingImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$ConnectionState_ConnectingImplCopyWithImpl<$Res>
    extends _$ConnectionStateCopyWithImpl<$Res,
        _$ConnectionState_ConnectingImpl>
    implements _$$ConnectionState_ConnectingImplCopyWith<$Res> {
  __$$ConnectionState_ConnectingImplCopyWithImpl(
      _$ConnectionState_ConnectingImpl _value,
      $Res Function(_$ConnectionState_ConnectingImpl) _then)
      : super(_value, _then);

  /// Create a copy of ConnectionState
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$ConnectionState_ConnectingImpl extends ConnectionState_Connecting {
  const _$ConnectionState_ConnectingImpl() : super._();

  @override
  String toString() {
    return 'ConnectionState.connecting()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$ConnectionState_ConnectingImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() connected,
    required TResult Function() disconnected,
    required TResult Function() connecting,
    required TResult Function(LinuxLinkErrorDto field0) error,
  }) {
    return connecting();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? connected,
    TResult? Function()? disconnected,
    TResult? Function()? connecting,
    TResult? Function(LinuxLinkErrorDto field0)? error,
  }) {
    return connecting?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? connected,
    TResult Function()? disconnected,
    TResult Function()? connecting,
    TResult Function(LinuxLinkErrorDto field0)? error,
    required TResult orElse(),
  }) {
    if (connecting != null) {
      return connecting();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(ConnectionState_Connected value) connected,
    required TResult Function(ConnectionState_Disconnected value) disconnected,
    required TResult Function(ConnectionState_Connecting value) connecting,
    required TResult Function(ConnectionState_Error value) error,
  }) {
    return connecting(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(ConnectionState_Connected value)? connected,
    TResult? Function(ConnectionState_Disconnected value)? disconnected,
    TResult? Function(ConnectionState_Connecting value)? connecting,
    TResult? Function(ConnectionState_Error value)? error,
  }) {
    return connecting?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(ConnectionState_Connected value)? connected,
    TResult Function(ConnectionState_Disconnected value)? disconnected,
    TResult Function(ConnectionState_Connecting value)? connecting,
    TResult Function(ConnectionState_Error value)? error,
    required TResult orElse(),
  }) {
    if (connecting != null) {
      return connecting(this);
    }
    return orElse();
  }
}

abstract class ConnectionState_Connecting extends ConnectionState {
  const factory ConnectionState_Connecting() = _$ConnectionState_ConnectingImpl;
  const ConnectionState_Connecting._() : super._();
}

/// @nodoc
abstract class _$$ConnectionState_ErrorImplCopyWith<$Res> {
  factory _$$ConnectionState_ErrorImplCopyWith(
          _$ConnectionState_ErrorImpl value,
          $Res Function(_$ConnectionState_ErrorImpl) then) =
      __$$ConnectionState_ErrorImplCopyWithImpl<$Res>;
  @useResult
  $Res call({LinuxLinkErrorDto field0});
}

/// @nodoc
class __$$ConnectionState_ErrorImplCopyWithImpl<$Res>
    extends _$ConnectionStateCopyWithImpl<$Res, _$ConnectionState_ErrorImpl>
    implements _$$ConnectionState_ErrorImplCopyWith<$Res> {
  __$$ConnectionState_ErrorImplCopyWithImpl(_$ConnectionState_ErrorImpl _value,
      $Res Function(_$ConnectionState_ErrorImpl) _then)
      : super(_value, _then);

  /// Create a copy of ConnectionState
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? field0 = null,
  }) {
    return _then(_$ConnectionState_ErrorImpl(
      null == field0
          ? _value.field0
          : field0 // ignore: cast_nullable_to_non_nullable
              as LinuxLinkErrorDto,
    ));
  }
}

/// @nodoc

class _$ConnectionState_ErrorImpl extends ConnectionState_Error {
  const _$ConnectionState_ErrorImpl(this.field0) : super._();

  @override
  final LinuxLinkErrorDto field0;

  @override
  String toString() {
    return 'ConnectionState.error(field0: $field0)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$ConnectionState_ErrorImpl &&
            (identical(other.field0, field0) || other.field0 == field0));
  }

  @override
  int get hashCode => Object.hash(runtimeType, field0);

  /// Create a copy of ConnectionState
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$ConnectionState_ErrorImplCopyWith<_$ConnectionState_ErrorImpl>
      get copyWith => __$$ConnectionState_ErrorImplCopyWithImpl<
          _$ConnectionState_ErrorImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() connected,
    required TResult Function() disconnected,
    required TResult Function() connecting,
    required TResult Function(LinuxLinkErrorDto field0) error,
  }) {
    return error(field0);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? connected,
    TResult? Function()? disconnected,
    TResult? Function()? connecting,
    TResult? Function(LinuxLinkErrorDto field0)? error,
  }) {
    return error?.call(field0);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? connected,
    TResult Function()? disconnected,
    TResult Function()? connecting,
    TResult Function(LinuxLinkErrorDto field0)? error,
    required TResult orElse(),
  }) {
    if (error != null) {
      return error(field0);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(ConnectionState_Connected value) connected,
    required TResult Function(ConnectionState_Disconnected value) disconnected,
    required TResult Function(ConnectionState_Connecting value) connecting,
    required TResult Function(ConnectionState_Error value) error,
  }) {
    return error(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(ConnectionState_Connected value)? connected,
    TResult? Function(ConnectionState_Disconnected value)? disconnected,
    TResult? Function(ConnectionState_Connecting value)? connecting,
    TResult? Function(ConnectionState_Error value)? error,
  }) {
    return error?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(ConnectionState_Connected value)? connected,
    TResult Function(ConnectionState_Disconnected value)? disconnected,
    TResult Function(ConnectionState_Connecting value)? connecting,
    TResult Function(ConnectionState_Error value)? error,
    required TResult orElse(),
  }) {
    if (error != null) {
      return error(this);
    }
    return orElse();
  }
}

abstract class ConnectionState_Error extends ConnectionState {
  const factory ConnectionState_Error(final LinuxLinkErrorDto field0) =
      _$ConnectionState_ErrorImpl;
  const ConnectionState_Error._() : super._();

  LinuxLinkErrorDto get field0;

  /// Create a copy of ConnectionState
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$ConnectionState_ErrorImplCopyWith<_$ConnectionState_ErrorImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
mixin _$SessionStatus {
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() disconnected,
    required TResult Function() connecting,
    required TResult Function() active,
    required TResult Function(BigInt rttMs) stale,
    required TResult Function(int attempt, BigInt nextRetryMs) reconnecting,
    required TResult Function(LinuxLinkErrorDto field0) error,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? disconnected,
    TResult? Function()? connecting,
    TResult? Function()? active,
    TResult? Function(BigInt rttMs)? stale,
    TResult? Function(int attempt, BigInt nextRetryMs)? reconnecting,
    TResult? Function(LinuxLinkErrorDto field0)? error,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? disconnected,
    TResult Function()? connecting,
    TResult Function()? active,
    TResult Function(BigInt rttMs)? stale,
    TResult Function(int attempt, BigInt nextRetryMs)? reconnecting,
    TResult Function(LinuxLinkErrorDto field0)? error,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SessionStatus_Disconnected value) disconnected,
    required TResult Function(SessionStatus_Connecting value) connecting,
    required TResult Function(SessionStatus_Active value) active,
    required TResult Function(SessionStatus_Stale value) stale,
    required TResult Function(SessionStatus_Reconnecting value) reconnecting,
    required TResult Function(SessionStatus_Error value) error,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(SessionStatus_Disconnected value)? disconnected,
    TResult? Function(SessionStatus_Connecting value)? connecting,
    TResult? Function(SessionStatus_Active value)? active,
    TResult? Function(SessionStatus_Stale value)? stale,
    TResult? Function(SessionStatus_Reconnecting value)? reconnecting,
    TResult? Function(SessionStatus_Error value)? error,
  }) =>
      throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SessionStatus_Disconnected value)? disconnected,
    TResult Function(SessionStatus_Connecting value)? connecting,
    TResult Function(SessionStatus_Active value)? active,
    TResult Function(SessionStatus_Stale value)? stale,
    TResult Function(SessionStatus_Reconnecting value)? reconnecting,
    TResult Function(SessionStatus_Error value)? error,
    required TResult orElse(),
  }) =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $SessionStatusCopyWith<$Res> {
  factory $SessionStatusCopyWith(
          SessionStatus value, $Res Function(SessionStatus) then) =
      _$SessionStatusCopyWithImpl<$Res, SessionStatus>;
}

/// @nodoc
class _$SessionStatusCopyWithImpl<$Res, $Val extends SessionStatus>
    implements $SessionStatusCopyWith<$Res> {
  _$SessionStatusCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of SessionStatus
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc
abstract class _$$SessionStatus_DisconnectedImplCopyWith<$Res> {
  factory _$$SessionStatus_DisconnectedImplCopyWith(
          _$SessionStatus_DisconnectedImpl value,
          $Res Function(_$SessionStatus_DisconnectedImpl) then) =
      __$$SessionStatus_DisconnectedImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$SessionStatus_DisconnectedImplCopyWithImpl<$Res>
    extends _$SessionStatusCopyWithImpl<$Res, _$SessionStatus_DisconnectedImpl>
    implements _$$SessionStatus_DisconnectedImplCopyWith<$Res> {
  __$$SessionStatus_DisconnectedImplCopyWithImpl(
      _$SessionStatus_DisconnectedImpl _value,
      $Res Function(_$SessionStatus_DisconnectedImpl) _then)
      : super(_value, _then);

  /// Create a copy of SessionStatus
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$SessionStatus_DisconnectedImpl extends SessionStatus_Disconnected {
  const _$SessionStatus_DisconnectedImpl() : super._();

  @override
  String toString() {
    return 'SessionStatus.disconnected()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SessionStatus_DisconnectedImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() disconnected,
    required TResult Function() connecting,
    required TResult Function() active,
    required TResult Function(BigInt rttMs) stale,
    required TResult Function(int attempt, BigInt nextRetryMs) reconnecting,
    required TResult Function(LinuxLinkErrorDto field0) error,
  }) {
    return disconnected();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? disconnected,
    TResult? Function()? connecting,
    TResult? Function()? active,
    TResult? Function(BigInt rttMs)? stale,
    TResult? Function(int attempt, BigInt nextRetryMs)? reconnecting,
    TResult? Function(LinuxLinkErrorDto field0)? error,
  }) {
    return disconnected?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? disconnected,
    TResult Function()? connecting,
    TResult Function()? active,
    TResult Function(BigInt rttMs)? stale,
    TResult Function(int attempt, BigInt nextRetryMs)? reconnecting,
    TResult Function(LinuxLinkErrorDto field0)? error,
    required TResult orElse(),
  }) {
    if (disconnected != null) {
      return disconnected();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SessionStatus_Disconnected value) disconnected,
    required TResult Function(SessionStatus_Connecting value) connecting,
    required TResult Function(SessionStatus_Active value) active,
    required TResult Function(SessionStatus_Stale value) stale,
    required TResult Function(SessionStatus_Reconnecting value) reconnecting,
    required TResult Function(SessionStatus_Error value) error,
  }) {
    return disconnected(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(SessionStatus_Disconnected value)? disconnected,
    TResult? Function(SessionStatus_Connecting value)? connecting,
    TResult? Function(SessionStatus_Active value)? active,
    TResult? Function(SessionStatus_Stale value)? stale,
    TResult? Function(SessionStatus_Reconnecting value)? reconnecting,
    TResult? Function(SessionStatus_Error value)? error,
  }) {
    return disconnected?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SessionStatus_Disconnected value)? disconnected,
    TResult Function(SessionStatus_Connecting value)? connecting,
    TResult Function(SessionStatus_Active value)? active,
    TResult Function(SessionStatus_Stale value)? stale,
    TResult Function(SessionStatus_Reconnecting value)? reconnecting,
    TResult Function(SessionStatus_Error value)? error,
    required TResult orElse(),
  }) {
    if (disconnected != null) {
      return disconnected(this);
    }
    return orElse();
  }
}

abstract class SessionStatus_Disconnected extends SessionStatus {
  const factory SessionStatus_Disconnected() = _$SessionStatus_DisconnectedImpl;
  const SessionStatus_Disconnected._() : super._();
}

/// @nodoc
abstract class _$$SessionStatus_ConnectingImplCopyWith<$Res> {
  factory _$$SessionStatus_ConnectingImplCopyWith(
          _$SessionStatus_ConnectingImpl value,
          $Res Function(_$SessionStatus_ConnectingImpl) then) =
      __$$SessionStatus_ConnectingImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$SessionStatus_ConnectingImplCopyWithImpl<$Res>
    extends _$SessionStatusCopyWithImpl<$Res, _$SessionStatus_ConnectingImpl>
    implements _$$SessionStatus_ConnectingImplCopyWith<$Res> {
  __$$SessionStatus_ConnectingImplCopyWithImpl(
      _$SessionStatus_ConnectingImpl _value,
      $Res Function(_$SessionStatus_ConnectingImpl) _then)
      : super(_value, _then);

  /// Create a copy of SessionStatus
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$SessionStatus_ConnectingImpl extends SessionStatus_Connecting {
  const _$SessionStatus_ConnectingImpl() : super._();

  @override
  String toString() {
    return 'SessionStatus.connecting()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SessionStatus_ConnectingImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() disconnected,
    required TResult Function() connecting,
    required TResult Function() active,
    required TResult Function(BigInt rttMs) stale,
    required TResult Function(int attempt, BigInt nextRetryMs) reconnecting,
    required TResult Function(LinuxLinkErrorDto field0) error,
  }) {
    return connecting();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? disconnected,
    TResult? Function()? connecting,
    TResult? Function()? active,
    TResult? Function(BigInt rttMs)? stale,
    TResult? Function(int attempt, BigInt nextRetryMs)? reconnecting,
    TResult? Function(LinuxLinkErrorDto field0)? error,
  }) {
    return connecting?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? disconnected,
    TResult Function()? connecting,
    TResult Function()? active,
    TResult Function(BigInt rttMs)? stale,
    TResult Function(int attempt, BigInt nextRetryMs)? reconnecting,
    TResult Function(LinuxLinkErrorDto field0)? error,
    required TResult orElse(),
  }) {
    if (connecting != null) {
      return connecting();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SessionStatus_Disconnected value) disconnected,
    required TResult Function(SessionStatus_Connecting value) connecting,
    required TResult Function(SessionStatus_Active value) active,
    required TResult Function(SessionStatus_Stale value) stale,
    required TResult Function(SessionStatus_Reconnecting value) reconnecting,
    required TResult Function(SessionStatus_Error value) error,
  }) {
    return connecting(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(SessionStatus_Disconnected value)? disconnected,
    TResult? Function(SessionStatus_Connecting value)? connecting,
    TResult? Function(SessionStatus_Active value)? active,
    TResult? Function(SessionStatus_Stale value)? stale,
    TResult? Function(SessionStatus_Reconnecting value)? reconnecting,
    TResult? Function(SessionStatus_Error value)? error,
  }) {
    return connecting?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SessionStatus_Disconnected value)? disconnected,
    TResult Function(SessionStatus_Connecting value)? connecting,
    TResult Function(SessionStatus_Active value)? active,
    TResult Function(SessionStatus_Stale value)? stale,
    TResult Function(SessionStatus_Reconnecting value)? reconnecting,
    TResult Function(SessionStatus_Error value)? error,
    required TResult orElse(),
  }) {
    if (connecting != null) {
      return connecting(this);
    }
    return orElse();
  }
}

abstract class SessionStatus_Connecting extends SessionStatus {
  const factory SessionStatus_Connecting() = _$SessionStatus_ConnectingImpl;
  const SessionStatus_Connecting._() : super._();
}

/// @nodoc
abstract class _$$SessionStatus_ActiveImplCopyWith<$Res> {
  factory _$$SessionStatus_ActiveImplCopyWith(_$SessionStatus_ActiveImpl value,
          $Res Function(_$SessionStatus_ActiveImpl) then) =
      __$$SessionStatus_ActiveImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$SessionStatus_ActiveImplCopyWithImpl<$Res>
    extends _$SessionStatusCopyWithImpl<$Res, _$SessionStatus_ActiveImpl>
    implements _$$SessionStatus_ActiveImplCopyWith<$Res> {
  __$$SessionStatus_ActiveImplCopyWithImpl(_$SessionStatus_ActiveImpl _value,
      $Res Function(_$SessionStatus_ActiveImpl) _then)
      : super(_value, _then);

  /// Create a copy of SessionStatus
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$SessionStatus_ActiveImpl extends SessionStatus_Active {
  const _$SessionStatus_ActiveImpl() : super._();

  @override
  String toString() {
    return 'SessionStatus.active()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SessionStatus_ActiveImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() disconnected,
    required TResult Function() connecting,
    required TResult Function() active,
    required TResult Function(BigInt rttMs) stale,
    required TResult Function(int attempt, BigInt nextRetryMs) reconnecting,
    required TResult Function(LinuxLinkErrorDto field0) error,
  }) {
    return active();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? disconnected,
    TResult? Function()? connecting,
    TResult? Function()? active,
    TResult? Function(BigInt rttMs)? stale,
    TResult? Function(int attempt, BigInt nextRetryMs)? reconnecting,
    TResult? Function(LinuxLinkErrorDto field0)? error,
  }) {
    return active?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? disconnected,
    TResult Function()? connecting,
    TResult Function()? active,
    TResult Function(BigInt rttMs)? stale,
    TResult Function(int attempt, BigInt nextRetryMs)? reconnecting,
    TResult Function(LinuxLinkErrorDto field0)? error,
    required TResult orElse(),
  }) {
    if (active != null) {
      return active();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SessionStatus_Disconnected value) disconnected,
    required TResult Function(SessionStatus_Connecting value) connecting,
    required TResult Function(SessionStatus_Active value) active,
    required TResult Function(SessionStatus_Stale value) stale,
    required TResult Function(SessionStatus_Reconnecting value) reconnecting,
    required TResult Function(SessionStatus_Error value) error,
  }) {
    return active(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(SessionStatus_Disconnected value)? disconnected,
    TResult? Function(SessionStatus_Connecting value)? connecting,
    TResult? Function(SessionStatus_Active value)? active,
    TResult? Function(SessionStatus_Stale value)? stale,
    TResult? Function(SessionStatus_Reconnecting value)? reconnecting,
    TResult? Function(SessionStatus_Error value)? error,
  }) {
    return active?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SessionStatus_Disconnected value)? disconnected,
    TResult Function(SessionStatus_Connecting value)? connecting,
    TResult Function(SessionStatus_Active value)? active,
    TResult Function(SessionStatus_Stale value)? stale,
    TResult Function(SessionStatus_Reconnecting value)? reconnecting,
    TResult Function(SessionStatus_Error value)? error,
    required TResult orElse(),
  }) {
    if (active != null) {
      return active(this);
    }
    return orElse();
  }
}

abstract class SessionStatus_Active extends SessionStatus {
  const factory SessionStatus_Active() = _$SessionStatus_ActiveImpl;
  const SessionStatus_Active._() : super._();
}

/// @nodoc
abstract class _$$SessionStatus_StaleImplCopyWith<$Res> {
  factory _$$SessionStatus_StaleImplCopyWith(_$SessionStatus_StaleImpl value,
          $Res Function(_$SessionStatus_StaleImpl) then) =
      __$$SessionStatus_StaleImplCopyWithImpl<$Res>;
  @useResult
  $Res call({BigInt rttMs});
}

/// @nodoc
class __$$SessionStatus_StaleImplCopyWithImpl<$Res>
    extends _$SessionStatusCopyWithImpl<$Res, _$SessionStatus_StaleImpl>
    implements _$$SessionStatus_StaleImplCopyWith<$Res> {
  __$$SessionStatus_StaleImplCopyWithImpl(_$SessionStatus_StaleImpl _value,
      $Res Function(_$SessionStatus_StaleImpl) _then)
      : super(_value, _then);

  /// Create a copy of SessionStatus
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? rttMs = null,
  }) {
    return _then(_$SessionStatus_StaleImpl(
      rttMs: null == rttMs
          ? _value.rttMs
          : rttMs // ignore: cast_nullable_to_non_nullable
              as BigInt,
    ));
  }
}

/// @nodoc

class _$SessionStatus_StaleImpl extends SessionStatus_Stale {
  const _$SessionStatus_StaleImpl({required this.rttMs}) : super._();

  @override
  final BigInt rttMs;

  @override
  String toString() {
    return 'SessionStatus.stale(rttMs: $rttMs)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SessionStatus_StaleImpl &&
            (identical(other.rttMs, rttMs) || other.rttMs == rttMs));
  }

  @override
  int get hashCode => Object.hash(runtimeType, rttMs);

  /// Create a copy of SessionStatus
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$SessionStatus_StaleImplCopyWith<_$SessionStatus_StaleImpl> get copyWith =>
      __$$SessionStatus_StaleImplCopyWithImpl<_$SessionStatus_StaleImpl>(
          this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() disconnected,
    required TResult Function() connecting,
    required TResult Function() active,
    required TResult Function(BigInt rttMs) stale,
    required TResult Function(int attempt, BigInt nextRetryMs) reconnecting,
    required TResult Function(LinuxLinkErrorDto field0) error,
  }) {
    return stale(rttMs);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? disconnected,
    TResult? Function()? connecting,
    TResult? Function()? active,
    TResult? Function(BigInt rttMs)? stale,
    TResult? Function(int attempt, BigInt nextRetryMs)? reconnecting,
    TResult? Function(LinuxLinkErrorDto field0)? error,
  }) {
    return stale?.call(rttMs);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? disconnected,
    TResult Function()? connecting,
    TResult Function()? active,
    TResult Function(BigInt rttMs)? stale,
    TResult Function(int attempt, BigInt nextRetryMs)? reconnecting,
    TResult Function(LinuxLinkErrorDto field0)? error,
    required TResult orElse(),
  }) {
    if (stale != null) {
      return stale(rttMs);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SessionStatus_Disconnected value) disconnected,
    required TResult Function(SessionStatus_Connecting value) connecting,
    required TResult Function(SessionStatus_Active value) active,
    required TResult Function(SessionStatus_Stale value) stale,
    required TResult Function(SessionStatus_Reconnecting value) reconnecting,
    required TResult Function(SessionStatus_Error value) error,
  }) {
    return stale(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(SessionStatus_Disconnected value)? disconnected,
    TResult? Function(SessionStatus_Connecting value)? connecting,
    TResult? Function(SessionStatus_Active value)? active,
    TResult? Function(SessionStatus_Stale value)? stale,
    TResult? Function(SessionStatus_Reconnecting value)? reconnecting,
    TResult? Function(SessionStatus_Error value)? error,
  }) {
    return stale?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SessionStatus_Disconnected value)? disconnected,
    TResult Function(SessionStatus_Connecting value)? connecting,
    TResult Function(SessionStatus_Active value)? active,
    TResult Function(SessionStatus_Stale value)? stale,
    TResult Function(SessionStatus_Reconnecting value)? reconnecting,
    TResult Function(SessionStatus_Error value)? error,
    required TResult orElse(),
  }) {
    if (stale != null) {
      return stale(this);
    }
    return orElse();
  }
}

abstract class SessionStatus_Stale extends SessionStatus {
  const factory SessionStatus_Stale({required final BigInt rttMs}) =
      _$SessionStatus_StaleImpl;
  const SessionStatus_Stale._() : super._();

  BigInt get rttMs;

  /// Create a copy of SessionStatus
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$SessionStatus_StaleImplCopyWith<_$SessionStatus_StaleImpl> get copyWith =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$SessionStatus_ReconnectingImplCopyWith<$Res> {
  factory _$$SessionStatus_ReconnectingImplCopyWith(
          _$SessionStatus_ReconnectingImpl value,
          $Res Function(_$SessionStatus_ReconnectingImpl) then) =
      __$$SessionStatus_ReconnectingImplCopyWithImpl<$Res>;
  @useResult
  $Res call({int attempt, BigInt nextRetryMs});
}

/// @nodoc
class __$$SessionStatus_ReconnectingImplCopyWithImpl<$Res>
    extends _$SessionStatusCopyWithImpl<$Res, _$SessionStatus_ReconnectingImpl>
    implements _$$SessionStatus_ReconnectingImplCopyWith<$Res> {
  __$$SessionStatus_ReconnectingImplCopyWithImpl(
      _$SessionStatus_ReconnectingImpl _value,
      $Res Function(_$SessionStatus_ReconnectingImpl) _then)
      : super(_value, _then);

  /// Create a copy of SessionStatus
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? attempt = null,
    Object? nextRetryMs = null,
  }) {
    return _then(_$SessionStatus_ReconnectingImpl(
      attempt: null == attempt
          ? _value.attempt
          : attempt // ignore: cast_nullable_to_non_nullable
              as int,
      nextRetryMs: null == nextRetryMs
          ? _value.nextRetryMs
          : nextRetryMs // ignore: cast_nullable_to_non_nullable
              as BigInt,
    ));
  }
}

/// @nodoc

class _$SessionStatus_ReconnectingImpl extends SessionStatus_Reconnecting {
  const _$SessionStatus_ReconnectingImpl(
      {required this.attempt, required this.nextRetryMs})
      : super._();

  @override
  final int attempt;
  @override
  final BigInt nextRetryMs;

  @override
  String toString() {
    return 'SessionStatus.reconnecting(attempt: $attempt, nextRetryMs: $nextRetryMs)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SessionStatus_ReconnectingImpl &&
            (identical(other.attempt, attempt) || other.attempt == attempt) &&
            (identical(other.nextRetryMs, nextRetryMs) ||
                other.nextRetryMs == nextRetryMs));
  }

  @override
  int get hashCode => Object.hash(runtimeType, attempt, nextRetryMs);

  /// Create a copy of SessionStatus
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$SessionStatus_ReconnectingImplCopyWith<_$SessionStatus_ReconnectingImpl>
      get copyWith => __$$SessionStatus_ReconnectingImplCopyWithImpl<
          _$SessionStatus_ReconnectingImpl>(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() disconnected,
    required TResult Function() connecting,
    required TResult Function() active,
    required TResult Function(BigInt rttMs) stale,
    required TResult Function(int attempt, BigInt nextRetryMs) reconnecting,
    required TResult Function(LinuxLinkErrorDto field0) error,
  }) {
    return reconnecting(attempt, nextRetryMs);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? disconnected,
    TResult? Function()? connecting,
    TResult? Function()? active,
    TResult? Function(BigInt rttMs)? stale,
    TResult? Function(int attempt, BigInt nextRetryMs)? reconnecting,
    TResult? Function(LinuxLinkErrorDto field0)? error,
  }) {
    return reconnecting?.call(attempt, nextRetryMs);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? disconnected,
    TResult Function()? connecting,
    TResult Function()? active,
    TResult Function(BigInt rttMs)? stale,
    TResult Function(int attempt, BigInt nextRetryMs)? reconnecting,
    TResult Function(LinuxLinkErrorDto field0)? error,
    required TResult orElse(),
  }) {
    if (reconnecting != null) {
      return reconnecting(attempt, nextRetryMs);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SessionStatus_Disconnected value) disconnected,
    required TResult Function(SessionStatus_Connecting value) connecting,
    required TResult Function(SessionStatus_Active value) active,
    required TResult Function(SessionStatus_Stale value) stale,
    required TResult Function(SessionStatus_Reconnecting value) reconnecting,
    required TResult Function(SessionStatus_Error value) error,
  }) {
    return reconnecting(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(SessionStatus_Disconnected value)? disconnected,
    TResult? Function(SessionStatus_Connecting value)? connecting,
    TResult? Function(SessionStatus_Active value)? active,
    TResult? Function(SessionStatus_Stale value)? stale,
    TResult? Function(SessionStatus_Reconnecting value)? reconnecting,
    TResult? Function(SessionStatus_Error value)? error,
  }) {
    return reconnecting?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SessionStatus_Disconnected value)? disconnected,
    TResult Function(SessionStatus_Connecting value)? connecting,
    TResult Function(SessionStatus_Active value)? active,
    TResult Function(SessionStatus_Stale value)? stale,
    TResult Function(SessionStatus_Reconnecting value)? reconnecting,
    TResult Function(SessionStatus_Error value)? error,
    required TResult orElse(),
  }) {
    if (reconnecting != null) {
      return reconnecting(this);
    }
    return orElse();
  }
}

abstract class SessionStatus_Reconnecting extends SessionStatus {
  const factory SessionStatus_Reconnecting(
      {required final int attempt,
      required final BigInt nextRetryMs}) = _$SessionStatus_ReconnectingImpl;
  const SessionStatus_Reconnecting._() : super._();

  int get attempt;
  BigInt get nextRetryMs;

  /// Create a copy of SessionStatus
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$SessionStatus_ReconnectingImplCopyWith<_$SessionStatus_ReconnectingImpl>
      get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$SessionStatus_ErrorImplCopyWith<$Res> {
  factory _$$SessionStatus_ErrorImplCopyWith(_$SessionStatus_ErrorImpl value,
          $Res Function(_$SessionStatus_ErrorImpl) then) =
      __$$SessionStatus_ErrorImplCopyWithImpl<$Res>;
  @useResult
  $Res call({LinuxLinkErrorDto field0});
}

/// @nodoc
class __$$SessionStatus_ErrorImplCopyWithImpl<$Res>
    extends _$SessionStatusCopyWithImpl<$Res, _$SessionStatus_ErrorImpl>
    implements _$$SessionStatus_ErrorImplCopyWith<$Res> {
  __$$SessionStatus_ErrorImplCopyWithImpl(_$SessionStatus_ErrorImpl _value,
      $Res Function(_$SessionStatus_ErrorImpl) _then)
      : super(_value, _then);

  /// Create a copy of SessionStatus
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? field0 = null,
  }) {
    return _then(_$SessionStatus_ErrorImpl(
      null == field0
          ? _value.field0
          : field0 // ignore: cast_nullable_to_non_nullable
              as LinuxLinkErrorDto,
    ));
  }
}

/// @nodoc

class _$SessionStatus_ErrorImpl extends SessionStatus_Error {
  const _$SessionStatus_ErrorImpl(this.field0) : super._();

  @override
  final LinuxLinkErrorDto field0;

  @override
  String toString() {
    return 'SessionStatus.error(field0: $field0)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$SessionStatus_ErrorImpl &&
            (identical(other.field0, field0) || other.field0 == field0));
  }

  @override
  int get hashCode => Object.hash(runtimeType, field0);

  /// Create a copy of SessionStatus
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$SessionStatus_ErrorImplCopyWith<_$SessionStatus_ErrorImpl> get copyWith =>
      __$$SessionStatus_ErrorImplCopyWithImpl<_$SessionStatus_ErrorImpl>(
          this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() disconnected,
    required TResult Function() connecting,
    required TResult Function() active,
    required TResult Function(BigInt rttMs) stale,
    required TResult Function(int attempt, BigInt nextRetryMs) reconnecting,
    required TResult Function(LinuxLinkErrorDto field0) error,
  }) {
    return error(field0);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? disconnected,
    TResult? Function()? connecting,
    TResult? Function()? active,
    TResult? Function(BigInt rttMs)? stale,
    TResult? Function(int attempt, BigInt nextRetryMs)? reconnecting,
    TResult? Function(LinuxLinkErrorDto field0)? error,
  }) {
    return error?.call(field0);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? disconnected,
    TResult Function()? connecting,
    TResult Function()? active,
    TResult Function(BigInt rttMs)? stale,
    TResult Function(int attempt, BigInt nextRetryMs)? reconnecting,
    TResult Function(LinuxLinkErrorDto field0)? error,
    required TResult orElse(),
  }) {
    if (error != null) {
      return error(field0);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(SessionStatus_Disconnected value) disconnected,
    required TResult Function(SessionStatus_Connecting value) connecting,
    required TResult Function(SessionStatus_Active value) active,
    required TResult Function(SessionStatus_Stale value) stale,
    required TResult Function(SessionStatus_Reconnecting value) reconnecting,
    required TResult Function(SessionStatus_Error value) error,
  }) {
    return error(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(SessionStatus_Disconnected value)? disconnected,
    TResult? Function(SessionStatus_Connecting value)? connecting,
    TResult? Function(SessionStatus_Active value)? active,
    TResult? Function(SessionStatus_Stale value)? stale,
    TResult? Function(SessionStatus_Reconnecting value)? reconnecting,
    TResult? Function(SessionStatus_Error value)? error,
  }) {
    return error?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(SessionStatus_Disconnected value)? disconnected,
    TResult Function(SessionStatus_Connecting value)? connecting,
    TResult Function(SessionStatus_Active value)? active,
    TResult Function(SessionStatus_Stale value)? stale,
    TResult Function(SessionStatus_Reconnecting value)? reconnecting,
    TResult Function(SessionStatus_Error value)? error,
    required TResult orElse(),
  }) {
    if (error != null) {
      return error(this);
    }
    return orElse();
  }
}

abstract class SessionStatus_Error extends SessionStatus {
  const factory SessionStatus_Error(final LinuxLinkErrorDto field0) =
      _$SessionStatus_ErrorImpl;
  const SessionStatus_Error._() : super._();

  LinuxLinkErrorDto get field0;

  /// Create a copy of SessionStatus
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$SessionStatus_ErrorImplCopyWith<_$SessionStatus_ErrorImpl> get copyWith =>
      throw _privateConstructorUsedError;
}
