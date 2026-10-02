#import "PasskeyKeystoreMMKV.h"

#import <MMKVCore/MMKV.h>

#ifdef MMKV_APPLE
using PasskeyMMKV = mmkv::MMKV;
static constexpr auto PasskeyMMKVMultiProcess = mmkv::MMKV_MULTI_PROCESS;
#else
using PasskeyMMKV = MMKV;
static constexpr auto PasskeyMMKVMultiProcess = MMKV_MULTI_PROCESS;
#endif

@implementation PasskeyKeystoreMMKV

+ (nullable PasskeyMMKV *)keystoreForAppGroup:(NSString *)appGroup
                                        error:(NSError * _Nullable * _Nullable)error {
  NSURL *containerURL = [[NSFileManager defaultManager]
    containerURLForSecurityApplicationGroupIdentifier:appGroup];
  if (containerURL == nil) {
    if (error != nil) {
      *error = [NSError errorWithDomain:@"ReactNativePasskeyAutofill"
                                   code:2
                               userInfo:@{
                                 NSLocalizedDescriptionKey:
                                   [NSString stringWithFormat:@"App Group is not accessible: %@", appGroup]
                               }];
    }
    return nil;
  }

  std::string rootPath([containerURL.path UTF8String]);
  PasskeyMMKV::initializeMMKV(rootPath);
  return PasskeyMMKV::mmkvWithID("keystore", PasskeyMMKVMultiProcess, nullptr, &rootPath);
}

+ (BOOL)setString:(NSString *)value
           forKey:(NSString *)key
         appGroup:(NSString *)appGroup
            error:(NSError * _Nullable * _Nullable)error {
  PasskeyMMKV *keystore = [self keystoreForAppGroup:appGroup error:error];
  if (keystore == nullptr) {
    return NO;
  }

#ifdef MMKV_APPLE
  std::string cppValue([value UTF8String]);
  return keystore->set(cppValue, key);
#else
  std::string cppValue([value UTF8String]);
  std::string cppKey([key UTF8String]);
  return keystore->set(cppValue, std::string_view(cppKey));
#endif
}

+ (nullable NSString *)stringForKey:(NSString *)key
                           appGroup:(NSString *)appGroup
                              error:(NSError * _Nullable * _Nullable)error {
  PasskeyMMKV *keystore = [self keystoreForAppGroup:appGroup error:error];
  if (keystore == nullptr) {
    return nil;
  }

  std::string result;
#ifdef MMKV_APPLE
  if (!keystore->getString(key, result)) {
#else
  std::string cppKey([key UTF8String]);
  if (!keystore->getString(std::string_view(cppKey), result)) {
#endif
    return nil;
  }
  return [NSString stringWithUTF8String:result.c_str()];
}

+ (NSArray<NSString *> *)allKeysForAppGroup:(NSString *)appGroup
                                      error:(NSError * _Nullable * _Nullable)error {
  PasskeyMMKV *keystore = [self keystoreForAppGroup:appGroup error:error];
  if (keystore == nullptr) {
    return @[];
  }

#ifdef MMKV_APPLE
  NSArray *keys = keystore->allKeysObjC();
  return keys == nil ? @[] : keys;
#else
  std::vector<std::string> keys = keystore->allKeys();
  NSMutableArray<NSString *> *result = [NSMutableArray arrayWithCapacity:keys.size()];
  for (const auto &cppKey : keys) {
    NSString *keyString = [NSString stringWithUTF8String:cppKey.c_str()];
    if (keyString != nil) {
      [result addObject:keyString];
    }
  }
  return result;
#endif
}

+ (BOOL)removeValueForKey:(NSString *)key
                 appGroup:(NSString *)appGroup
                    error:(NSError * _Nullable * _Nullable)error {
  PasskeyMMKV *keystore = [self keystoreForAppGroup:appGroup error:error];
  if (keystore == nullptr) {
    return NO;
  }

#ifdef MMKV_APPLE
  keystore->removeValueForKey(key);
#else
  std::string cppKey([key UTF8String]);
  keystore->removeValueForKey(std::string_view(cppKey));
#endif
  return YES;
}

@end
