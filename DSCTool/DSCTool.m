//
//  DSCTool.m
//
#include <stdio.h>
#include <libc.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>

#import "DSCTool.h"
#import "CDClassDump.h"
#import "CDTypeFormatter.h"
#import "CDBalanceFormatter.h"
#import "CDOCInstanceVariable.h"
#import "CDOCProperty.h"

@interface DSCTool ()

@property(strong, nonatomic, nonnull) NSObject<HPHopperServices> *services;
@property(strong, nonatomic, nonnull) NSObject<HPDocument> *document;
@property(strong, nonatomic, nonnull) NSObject<HPDisassembledFile> *file;

@end


@implementation DSCTool

- (instancetype)initWithHopperServices:(NSObject<HPHopperServices> *)services {
  if (self = [super init]) {
    _services = services;
    _document = [self.services currentDocument];
    _file = [self.document disassembledFile];
  }

  return self;
}

+ (int)sdkVersion {
    return HOPPER_CURRENT_SDK_VERSION;
}

- (NSArray *)toolMenuDescription {
    return @[@{
      HPM_TITLE : @"Analyze address at cursor as __objc_class",
      HPM_SELECTOR : NSStringFromSelector(@selector(analyzeCurrentAddressAsObjcClass:))
    }, @{
      HPM_TITLE : @"Analyze address at cursor as __objc_protocol",
      HPM_SELECTOR : NSStringFromSelector(@selector(analyzeCurrentAddressAsObjcProto:))
    }, @{
      HPM_TITLE : @"Analyze all classes in __objc_classlist",
      HPM_SELECTOR : NSStringFromSelector(@selector(analyzeAllClasses:))
    }, @{
      HPM_TITLE : @"Analyze all protocols in __objc_protolist",
      HPM_SELECTOR : NSStringFromSelector(@selector(analyzeAllProtocols:))
    }];
}

- (nonnull NSObject<HPHopperUUID> *)pluginUUID {
    return [self.services UUIDWithString:@"b31e43f4-e2b8-4202-9452-841131d16d39"];
}

- (HopperPluginType)pluginType {
    return Plugin_Tool;
}

- (nonnull NSString *)pluginName {
    return @"DSCTool";
}

- (nonnull NSString *)pluginDescription {
    return @"Analyze ObjC runtime structs in the dyld_shared_cache";
}

- (nonnull NSString *)pluginAuthor {
    return @"@epsilan";
}

- (nonnull NSString *)pluginCopyright {
    return @"whatever";
}

- (nonnull NSString *)pluginVersion {
    return @"1.0.0";
}

/// Returns a string identifying the plugin for the command line tool.
/// For instance, the Mach-O loader returns "Mach-O".
/// You should avoid spaces in order to avoid quotes in the command line.
- (nonnull NSArray<NSString *> *)commandLineIdentifiers {
    return @[@"dsctool"];
}

/// Idempotent method that will dePAC and import |addr|, even if not pointer authenticated and/or already imported.
/// The result is written to |dest| to overwrite the previously authenticated address.
- (Address)dePACAndImportAddress:(Address)addr :(Address)dest {
    [self.document dePACAddress:addr storedAt:dest];
    Address dePACedAddress = [self.document readAddressAtVirtualAddress:dest];
#ifdef DEBUG
    [self.document logInfoMessage:[NSString stringWithFormat:@"addr: %llx, dest: %llx, dePAC: %llx", addr, dest, dePACedAddress ]];
#endif
    // some bug in this method: *** -[_NSInlineData subdataWithRange:]: range {0, 18446744073709523218} exceeds data length 8192
    @try {
        [self.document importAddressFromDYLDCache:dePACedAddress];
    } @catch (NSException *exception) {
        [self.document logErrorStringMessage:[NSString stringWithFormat:@"Error importing address: %llx", addr]];
        return 0;
    }
#ifdef DEBUG
    [self.document logStringMessage:[NSString stringWithFormat:@"Successful dePAC and import of %llx", addr]];
#endif
    return dePACedAddress;
}

/// Similar version of above method but address is returned instead of written
- (Address)dePACAndImportAddress:(Address)addr {
    Address dePACedAddress = [self.file dePACAddress:addr];
#if DEBUG
    [self.document logInfoMessage:[NSString stringWithFormat:@"dePACedAddress: %llx", dePACedAddress]];
#endif
    @try {
        [self.document importAddressFromDYLDCache:dePACedAddress];
    } @catch (NSException *exception) {
        [self.document logErrorStringMessage:[NSString stringWithFormat:@"Error importing address: %llx", addr]];
        return 0;
    }
    return dePACedAddress;
}

- (Address)pointerForTypeOffset:(Address)addr fieldName:(NSString *)field {
    NSObject<HPSegment> *seg = [self.file segmentForVirtualAddress:addr];
    NSObject<HPTypeDesc> *typeDesc = [seg structureTypeAt:addr];
    if (typeDesc == nil) {
        return 0;
    }
    Address offset = [typeDesc offsetForStructureFieldPathString:field];
    return addr + offset;
}

- (Address)dePACAndImportField:(Address)addr fieldName:(NSString *)field {
    Address ptr = [self pointerForTypeOffset:addr fieldName:field];
    Address value = [self.document readAddressAtVirtualAddress:ptr];
    return [self dePACAndImportAddress:value:ptr];
}

- (Address)analyzeAddressAsObjcClass:(Address)addr isMeta:(BOOL)meta {
    // read, dePAC, and import address from DSC
    Address objcClassAddr = [self.document readAddressAtVirtualAddress:addr];
    Address objcClassAddrDePAC = [self dePACAndImportAddress:objcClassAddr:addr];
    if (objcClassAddrDePAC == 0) {
        return 0;
    }
    // read address and define it as __objc_class
    NSObject<HPTypeDesc> *objcClassTypeDesc = [self.file typeWithName:@"__objc_class"];
    [self.file defineStructure:objcClassTypeDesc at:objcClassAddrDePAC];
    if ([self.file hasStructureDefinedAt:objcClassAddrDePAC]) {
        [self.document logStringMessage:[NSString stringWithFormat:@"Successfully defined objc_class at %llx", objcClassAddrDePAC]];
    } else {
        [self.document logErrorStringMessage:[NSString stringWithFormat:@"Error defining objc_class at %llx", objcClassAddrDePAC]];
        return 0;
    }
    
    // recursively call and retrieve meta & superclass names, only to a depth of 1
    NSString *metaclassName = nil, *superclassName = nil;
    if (!meta) {
        [self dePACAndImportField:objcClassAddrDePAC fieldName:@"metaclass"];
        Address metaclassPtr = [self pointerForTypeOffset:objcClassAddr fieldName:@"metaclass"];
        if (metaclassPtr != 0) {
            Address metaclassNameAddr = [self analyzeAddressAsObjcClass:metaclassPtr isMeta:true];
            metaclassName = [self.file readCStringAt:metaclassNameAddr];
        }
        [self dePACAndImportField:objcClassAddrDePAC fieldName:@"superclass"];
        Address superclassPtr = [self pointerForTypeOffset:objcClassAddr fieldName:@"superclass"];
        if (superclassPtr != 0) {
            Address superclassNameAddr = [self analyzeAddressAsObjcClass:superclassPtr isMeta:true];
            superclassName = [self.file readCStringAt:superclassNameAddr];
        }
    }
    
    // 3. dePAC, import then define objc_data
    Address objcDataAddrDePAC = [self dePACAndImportField:objcClassAddrDePAC fieldName:@"data"];
    if (objcDataAddrDePAC == 0) {
        return 0;
    }
    NSObject<HPTypeDesc> *objcDataType = [self.file typeWithName:@"__objc_data"];
    [self.file defineStructure:objcDataType at:objcDataAddrDePAC];
    
    // 5. dePAC, import, read, and set class name
    Address objcClassNameAddrDePAC = [self dePACAndImportField:objcDataAddrDePAC fieldName:@"name"];
    NSString *className = [self.document readCStringAt:objcClassNameAddrDePAC];
    [self.document logStringMessage:[NSString stringWithFormat:@"Found class: %@", className]];
    NSObject<HPSegment> *seg = [self.file segmentForVirtualAddress:objcClassNameAddrDePAC];
    [seg makeASCIIAt:objcClassNameAddrDePAC];
    // set class name and class ref if not already named
    [self.file setName:[NSString stringWithFormat:@"__objc_class_%@", className] forVirtualAddress:objcClassAddr reason:NCReason_Script];
    [self.file setName:[NSString stringWithFormat:@"__objc_clsref_%@", className] forVirtualAddress:addr reason:NCReason_Script];
    if (meta) {
        return objcClassNameAddrDePAC;
    }
    
    // 6. dePAC & import baseMethods
    NSArray *baseMethods = nil;
    Address baseMethodsAddr = [self dePACAndImportField:objcDataAddrDePAC fieldName:@"baseMethods"];
    if (baseMethodsAddr != 0) {
        baseMethods = [self analyzeMethods:baseMethodsAddr formatType:true];
    }
    
    // 7. ... ivars
    NSArray *ivars = nil;
    Address ivarAddr = [self dePACAndImportField:objcDataAddrDePAC fieldName:@"ivars"];
    if (ivarAddr != 0) {
        ivars = [self analyzeIvars:ivarAddr];
    }
    
    // 8. ... baseProperties
    NSArray *properties = nil;
    Address basePropertiesAddr = [self dePACAndImportField:objcDataAddrDePAC fieldName:@"baseProperties"];
    if (basePropertiesAddr != 0) {
        properties = [self analyzeProperties:basePropertiesAddr];
    }
    
    // 9. ... protocols
    NSArray *protocols = nil;
    Address protocolsAddr = [self dePACAndImportField:objcDataAddrDePAC fieldName:@"baseProtocols"];
    if (protocolsAddr != 0) {
        protocols = [self analyzeProtocols:protocolsAddr];
    }
    
    // build & comment class string representation
    NSMutableString *classRepr = [[NSMutableString alloc] init];
    [classRepr appendFormat:@"@class %@", className];
    if (superclassName != nil) {
        [classRepr appendFormat:@": %@", superclassName];
        if (protocols != nil) {
            [classRepr appendFormat:@"<%@>", [protocols componentsJoinedByString:@", "]];
        }
    }
    [classRepr appendString:@" {\n"];
    if (ivars != nil) {
        [ivars enumerateObjectsUsingBlock:^(NSString * _Nonnull ivar, NSUInteger idx, BOOL * _Nonnull stop) {
            [classRepr appendFormat:@"    ivar %@\n", ivar];
        }];
    }
    if (properties != nil) {
        [properties enumerateObjectsUsingBlock:^(NSString * _Nonnull prop, NSUInteger idx, BOOL * _Nonnull stop) {
            [classRepr appendFormat:@"    %@", prop];
        }];
    }
    if (baseMethods != nil) {
        [baseMethods enumerateObjectsUsingBlock:^(NSString * _Nonnull method, NSUInteger idx, BOOL * _Nonnull stop) {
            [classRepr appendFormat:@"    -%@\n", method];
        }];
    }
    [classRepr appendString:@"}"];
    [self.file setComment:classRepr atVirtualAddress:objcClassAddrDePAC reason:CCReason_User];
    
    return objcClassAddrDePAC;
}

- (NSArray<NSString *> *)analyzeMethods:(Address)addr formatType:(BOOL)format {
    NSObject<HPTypeDesc> *methodList = [self.file typeWithName:@"__objc_method_list"];
    [self.file defineStructure:methodList at:addr];
    Address count = [self.file readUnsignedValueForFieldPath:@"count" at:addr];
    BOOL relative = [self.file readUnsignedValueForFieldPath:@"flags" at:addr] & 0x80000000;  // smallMethodListFlag
    
    NSObject<HPTypeDesc> *methodType;
    if (relative) {
        methodType = [self.file typeWithName:@"__objc_relative_method"];
    } else {
        methodType = [self.file typeWithName:@"__objc_method"];
    }
    
    CDTypeFormatter *methodTypeFormatter = [[CDTypeFormatter alloc] init];
    methodTypeFormatter.shouldExpand = NO;
    methodTypeFormatter.shouldAutoExpand = NO;
    methodTypeFormatter.baseLevel = 0;
    
    NSString *name = nil, *signature = nil, *formattedSignature = nil;
    NSMutableArray *names = [[NSMutableArray alloc] init];
    Address curMethod = addr + [methodList sizeOf];
    for (int i = 0; i < count; i++) {
        [self.file defineStructure:methodType at:curMethod];
        if (relative) {
            // read name
            int32_t nameOffset = [self.document readInt32AtVirtualAddress:curMethod];
            if ([self.file hasMappedDataAt:curMethod + nameOffset]) {
                name = [self.file readCStringAt:curMethod + nameOffset];
            } else {
                Address nameAddr = [self dePACAndImportAddress:curMethod + nameOffset];
                if (nameAddr == 0) {
                    name = @"<unknown>";
                } else {
                    name = [self.file readCStringAt:nameAddr];
                }
            }
            // read signature
            Address signaturePtr = [self pointerForTypeOffset:curMethod fieldName:@"signature"];
            int32_t signatureOffset = [self.document readInt32AtVirtualAddress:signaturePtr];
            if ([self.file hasMappedDataAt:signaturePtr + signatureOffset]) {
                signature = [self.file readCStringAt:signaturePtr + signatureOffset];
            } else {
                Address signatureAddr = [self dePACAndImportAddress:signaturePtr + signatureOffset];
                if (signatureAddr == 0) {
                    signature = @"";
                } else {
                    signature = [self.file readCStringAt:signatureAddr];
                }
            }
            // format type for method
            formattedSignature = [methodTypeFormatter formatMethodName:name typeString:signature];
            
            // comment type signature at implementation
            Address implPtr = [self pointerForTypeOffset:curMethod fieldName:@"implementation"];
            int32_t implOffset = [self.document readInt32AtVirtualAddress:implPtr]; // usually negative hence signed int
            Address implAddr = implPtr + implOffset;
            // note: may not be mapped and importing doesn't quite solve the issue
            if ([self.file hasMappedDataAt:implAddr]) {
                [self.file setComment:formattedSignature atVirtualAddress:implAddr reason:CCReason_User];
            }
            // comment type signature inline
            [self.file setComment:[NSString stringWithFormat:@"%@ at %#llx", formattedSignature, implAddr] atVirtualAddress:curMethod reason:CCReason_User];
            
        } else {
            Address nameAddr = [self.file readUnsignedValueForFieldPath:@"name" at:curMethod];
            Address nameDePAC = [self dePACAndImportAddress:nameAddr :curMethod];
            
            name = [self.file readCStringAt:nameDePAC];
            [self.file setComment:name atVirtualAddress:curMethod reason:CCReason_User];
        }
        if (format && formattedSignature != nil) {
            [names addObject:formattedSignature];
        } else if (name != nil) {
            // readCString returns nil when the null terminator is missing, which can happen on a DYLD page boundary
            // TODO: implement func that reads up until null terminator or end of page, whichever comes first.
            [names addObject:name];
        } else {
            [names addObject:@"<unknown>"];
        }
        
        curMethod += [methodType sizeOf];
    }
    return names;
}

- (NSArray<NSString *> *)analyzeMethods:(Address)addr {
    return [self analyzeMethods:addr formatType:false];
}

- (NSArray<NSString *> *)analyzeIvars:(Address)addr {
    NSObject<HPTypeDesc> *ivar = [self.file typeWithName:@"__objc_ivar"];
    NSObject<HPTypeDesc> *ivars = [self.file typeWithName:@"__objc_ivars"];
    [self.file defineStructure:ivars at:addr];
    Address count = [self.file readUnsignedValueForFieldPath:@"count" at:addr];
    
    CDTypeFormatter *ivarTypeFormatter = [[CDTypeFormatter alloc] init];
    ivarTypeFormatter.shouldExpand = YES;
    ivarTypeFormatter.shouldAutoExpand = YES;
    ivarTypeFormatter.baseLevel = 0;
    
    NSMutableArray *ivarArr = [[NSMutableArray alloc] init];
    Address curIvar = addr + [ivars sizeOf];
    for (int i = 0; i < count; i++) {
        [self.file defineStructure:ivar at:curIvar];
        // dePAC & read offset pointer (at an offset of 0x0 from curIvar)
        Address offsetPtr = [self dePACAndImportField:curIvar fieldName:@"offset"];
        uint32_t offset = [self.file readUInt32AtVirtualAddress:offsetPtr];
        // dePAC & read name
        Address namePtr = [self dePACAndImportField:curIvar fieldName:@"name"];
        NSString *name = [self.file readCStringAt:namePtr];
        // read type
        Address typePtr = [self dePACAndImportField:curIvar fieldName:@"type"];
        NSString *type = [self.file readCStringAt:typePtr];
        CDOCInstanceVariable *var = [[CDOCInstanceVariable alloc] initWithName:name typeString:type offset:0];
        NSString *formattedType = [ivarTypeFormatter formatVariable:name type:var.type];
        // comment name & offset
        NSString *formattedIvar = [NSString stringWithFormat:@"%@ // offset: %#x", formattedType, offset];
        [self.file setComment:formattedIvar atVirtualAddress:curIvar reason:CCReason_User];
        
        [ivarArr addObject:formattedIvar];
        curIvar += [ivar sizeOf];
    }
    return ivarArr;
}

// adapted from Nygard's CDTextClassDumpVisitor._visitProperty method
- (NSString *)formatProperty:(CDOCProperty *)property typeFormatter:(CDTypeFormatter *)propertyTypeFormatter;
{
    NSString *backingVar = nil;
    BOOL isWeak = NO;
    BOOL isDynamic = NO;
    
    NSMutableArray *alist = [[NSMutableArray alloc] init];
    NSMutableArray *unknownAttrs = [[NSMutableArray alloc] init];
    NSMutableString *resultString = [[NSMutableString alloc] init];
    
    // objc_v2_encode_prop_attr() in gcc/objc/objc-act.c
    
    for (NSString *attr in property.attributes) {
        if ([attr hasPrefix:@"T"]) {
            [self.document logInfoMessage:@"Warning: Property attribute 'T' should occur only occur at the beginning"];
        } else if ([attr hasPrefix:@"R"]) {
            [alist addObject:@"readonly"];
        } else if ([attr hasPrefix:@"C"]) {
            [alist addObject:@"copy"];
        } else if ([attr hasPrefix:@"&"]) {
            [alist addObject:@"retain"];
        } else if ([attr hasPrefix:@"G"]) {
            [alist addObject:[NSString stringWithFormat:@"getter=%@", [attr substringFromIndex:1]]];
        } else if ([attr hasPrefix:@"S"]) {
            [alist addObject:[NSString stringWithFormat:@"setter=%@", [attr substringFromIndex:1]]];
        } else if ([attr hasPrefix:@"V"]) {
            backingVar = [attr substringFromIndex:1];
        } else if ([attr hasPrefix:@"N"]) {
            [alist addObject:@"nonatomic"];
        } else if ([attr hasPrefix:@"W"]) {
            // @property(assign) __weak NSObject *prop;
            // Only appears with GC.
            isWeak = YES;
        } else if ([attr hasPrefix:@"P"]) {
            // @property(assign) __strong NSObject *prop;
            // Only appears with GC.
            // This is the default.
            isWeak = NO;
        } else if ([attr hasPrefix:@"D"]) {
            // Dynamic property.  Implementation supplied at runtime.
            // @property int prop; // @dynamic prop;
            isDynamic = YES;
        } else {
            [self.document logInfoMessage:[NSString stringWithFormat:@"Warning: Unknown property attribute '%@'", attr]];
            [unknownAttrs addObject:attr];
        }
    }
    
    if ([alist count] > 0) {
        [resultString appendFormat:@"@property(%@) ", [alist componentsJoinedByString:@", "]];
    } else {
        [resultString appendString:@"@property "];
    }
    
    if (isWeak)
        [resultString appendString:@"__weak "];
    
    NSString *formattedString = [propertyTypeFormatter formatVariable:property.name type:property.type];
    [resultString appendFormat:@"%@;", formattedString];
    
    if (isDynamic) {
        [resultString appendFormat:@" // @dynamic %@;", property.name];
    } else if (backingVar != nil) {
        if ([backingVar isEqualToString:property.name]) {
            [resultString appendFormat:@" // @synthesize %@;", property.name];
        } else {
            [resultString appendFormat:@" // @synthesize %@=%@;", property.name, backingVar];
        }
    }
    
    [resultString appendString:@"\n"];
    if ([unknownAttrs count] > 0) {
        [resultString appendFormat:@"// Preceding property had unknown attributes: %@\n", [unknownAttrs componentsJoinedByString:@","]];
        if ([property.attributeString length] > 80) {
            [resultString appendFormat:@"// Original attribute string (following type): %@\n\n", property.attributeStringAfterType];
        } else {
            [resultString appendFormat:@"// Original attribute string: %@\n\n", property.attributeString];
        }
    }
    
    return resultString;
}

- (NSArray<NSString *> *)analyzeProperties:(Address)addr {
    NSObject<HPTypeDesc> *property = [self.file typeWithName:@"__objc_property"];
    NSObject<HPTypeDesc> *propertyList = [self.file typeWithName:@"__objc_property_list"];
    [self.file defineStructure:propertyList at:addr];
    Address count = [self.file readUnsignedValueForFieldPath:@"count" at:addr];
    
    CDTypeFormatter *propertyTypeFormatter = [[CDTypeFormatter alloc] init];
    propertyTypeFormatter.shouldExpand = NO;
    propertyTypeFormatter.shouldAutoExpand = NO;
    propertyTypeFormatter.baseLevel = 0;
    
    NSMutableArray *propertyArr = [[NSMutableArray alloc] init];
    NSObject<HPSegment> *seg = nil;
    Address curProperty = addr + [propertyList sizeOf];
    for (int i = 0; i < count; i++) {
        [self.file defineStructure:property at:curProperty];
        // dePAC & import name
        Address namePtr = [self dePACAndImportField:curProperty fieldName:@"name"];
        NSString *name = [self.file readCStringAt:namePtr];
        seg = [self.file segmentForVirtualAddress:namePtr];
        [seg makeASCIIAt:namePtr];
        // dePAC & import attributes
        Address attributesPtr = [self dePACAndImportField:curProperty fieldName:@"attributes"];
        NSString *attributes = [self.file readCStringAt:attributesPtr];
        CDOCProperty *prop = [[CDOCProperty alloc] initWithName:name attributes:attributes];
        // format type
        NSString *formattedType = [self formatProperty:prop typeFormatter:propertyTypeFormatter];
        [self.file setComment:formattedType atVirtualAddress:curProperty reason:CCReason_User];
        
        [propertyArr addObject:formattedType];
        curProperty += [property sizeOf];
    }
    return propertyArr;
}

- (NSString *)analyzeProtocol:(Address)addr {
    NSObject<HPTypeDesc> *protocol = [self.file typeWithName:@"__objc_protocol"];
    NSObject<HPTypeDesc> *protocolExt = [self.file typeWithName:@"__objc_protocol_ext"];
    
    Address curProtocol = [self.file readAddressAtVirtualAddress:addr];
    Address dePACedProtocol = [self dePACAndImportAddress:curProtocol :addr];
    BOOL ext = [self.file isExtendedProtocolAt:dePACedProtocol];
    if (ext) {
        [self.file defineStructure:protocolExt at:dePACedProtocol];
    } else {
        [self.file defineStructure:protocol at:dePACedProtocol];
    }
    // name
    Address nameAddr = [self dePACAndImportField:dePACedProtocol fieldName:@"name"];
    NSString *name = [self.document readCStringAt:nameAddr];
#if DEBUG
    [self.document logStringMessage:[NSString stringWithFormat:@"Protocol: %@", name]];
#endif
    NSObject<HPSegment> *seg = [self.file segmentForVirtualAddress:nameAddr];
    [seg makeASCIIAt:nameAddr];
    
    // protocols
    NSArray *subprotocolNames = nil;
    Address protocolsAddr = [self dePACAndImportField:dePACedProtocol fieldName:@"protocols"];
    if (protocolsAddr != 0) {
        subprotocolNames = [self.file protocolNamesDefinedInNewRuntimeProtocolListAt:protocolsAddr];
#if DEBUG
        [self.document logStringMessage:[NSString stringWithFormat:@"Protocol names: %@", subprotocolNames]];
#endif
    }
    // analyze each methods ptr
    NSArray *instanceMethods, *classMethods, *optionalInstanceMethods, *optionalClassMethods;
    instanceMethods = classMethods = optionalInstanceMethods = optionalClassMethods = nil;
    NSMutableArray *allMethods = [[NSMutableArray alloc] init];
    // ... instanceMethods
    Address instanceMethodsAddr = [self dePACAndImportField:dePACedProtocol fieldName:@"instanceMethods"];
    if (instanceMethodsAddr != 0) {
        instanceMethods = [self analyzeMethods:instanceMethodsAddr];
        [allMethods addObjectsFromArray:instanceMethods];
    }
    // ... classMethods
    Address classMethodsAddr = [self dePACAndImportField:dePACedProtocol fieldName:@"classMethods"];
    if (classMethodsAddr != 0) {
        classMethods = [self analyzeMethods:classMethodsAddr];
        [allMethods addObjectsFromArray:classMethods];
    }
    // ... optionalInstanceMethods
    Address optionalInstanceMethodsAddr = [self dePACAndImportField:dePACedProtocol fieldName:@"optionalInstanceMethods"];
    if (optionalInstanceMethodsAddr != 0) {
        optionalInstanceMethods = [self analyzeMethods:optionalInstanceMethodsAddr];
        [allMethods addObjectsFromArray:optionalInstanceMethods];
    }
    // ... optionalClassMethods
    Address optionalClassMethodsAddr = [self dePACAndImportField:dePACedProtocol fieldName:@"optionalClassMethods"];
    if (optionalClassMethodsAddr != 0) {
        optionalClassMethods = [self analyzeMethods:optionalClassMethodsAddr];
        [allMethods addObjectsFromArray:optionalClassMethods];
    }

    // extract optional extended method types, const char **_extendedMethodTypes;
    NSMutableDictionary *extMethodToTypeDict = [[NSMutableDictionary alloc] init];
    Address extendedMethodTypesAddr = [self dePACAndImportField:dePACedProtocol fieldName:@"extendedMethodTypes"];
    if (extendedMethodTypesAddr != 0) {
#if DEBUG
        [self.document logStringMessage:[NSString stringWithFormat:@"allMethods: %@", allMethods]];
#endif
        CDTypeFormatter *methodTypeFormatter = [[CDTypeFormatter alloc] init];
        methodTypeFormatter.shouldExpand = NO;
        methodTypeFormatter.shouldAutoExpand = NO;
        methodTypeFormatter.baseLevel = 0;
        
        __block Address curMethodTypePtr = extendedMethodTypesAddr;
        [allMethods enumerateObjectsUsingBlock:^(NSString * _Nonnull method, NSUInteger idx, BOOL * _Nonnull stop) {
            Address curMethodType = [self.file readAddressAtVirtualAddress:curMethodTypePtr];
            curMethodType = [self dePACAndImportAddress:curMethodType :curMethodTypePtr];
            NSString *typeStr = [self.file readCStringAt:curMethodType];
            NSString *formattedType = [methodTypeFormatter formatMethodName:method typeString:typeStr];
            
            [extMethodToTypeDict setObject:formattedType forKey:method];
            curMethodTypePtr += sizeof(void *);
        }];
#if DEBUG
        [self.document logStringMessage:[NSString stringWithFormat:@"Method types:\n%@", extMethodToTypeDict]];
#endif
    }
    // build protocol string representation
    NSMutableString *protocolRepr = [[NSMutableString alloc] init];
    [protocolRepr appendFormat:@"@protocol %@", name];
    if (subprotocolNames != nil) {
        [protocolRepr appendFormat:@"<%@>", [subprotocolNames componentsJoinedByString:@", "]];
    }
    [protocolRepr appendString:@" {\n"];
    if (instanceMethods != nil) {
        [instanceMethods enumerateObjectsUsingBlock:^(NSString * _Nonnull method, NSUInteger idx, BOOL * _Nonnull stop) {
            if (extMethodToTypeDict != nil) {
                [protocolRepr appendFormat:@"    -%@\n", [extMethodToTypeDict objectForKey:method]];
            } else {
                [protocolRepr appendFormat:@"    -%@\n", method];
            }
        }];
    }
    if (classMethods != nil) {
        [classMethods enumerateObjectsUsingBlock:^(NSString * _Nonnull method, NSUInteger idx, BOOL * _Nonnull stop) {
            if (extMethodToTypeDict != nil) {
                [protocolRepr appendFormat:@"    +%@\n", [extMethodToTypeDict objectForKey:method]];
            } else {
                [protocolRepr appendFormat:@"    +%@\n", method];
            }
        }];
    }
    if (optionalClassMethods != nil || optionalInstanceMethods != nil) {
        [protocolRepr appendString:@"    @optional\n"];
    }
    if (optionalInstanceMethods != nil) {
        [optionalInstanceMethods enumerateObjectsUsingBlock:^(NSString * _Nonnull method, NSUInteger idx, BOOL * _Nonnull stop) {
            if (extMethodToTypeDict != nil) {
                [protocolRepr appendFormat:@"    -%@\n", [extMethodToTypeDict objectForKey:method]];
            } else {
                [protocolRepr appendFormat:@"    -%@\n", method];
            }
        }];
    }
    if (optionalClassMethods != nil) {
        [optionalClassMethods enumerateObjectsUsingBlock:^(NSString * _Nonnull method, NSUInteger idx, BOOL * _Nonnull stop) {
            if (extMethodToTypeDict != nil) {
                [protocolRepr appendFormat:@"    +%@\n", [extMethodToTypeDict objectForKey:method]];
            } else {
                [protocolRepr appendFormat:@"    +%@\n", method];
            }
        }];
    }
    [protocolRepr appendString:@"}"];
    [self.file setComment:protocolRepr atVirtualAddress:dePACedProtocol reason:CCReason_User];
    
    return name;
}

- (NSArray<NSString *> *)analyzeProtocols:(Address)addr {
    NSObject<HPTypeDesc> *protocolList = [self.file typeWithName:@"__objc_protocol_list"];
    [self.file defineStructure:protocolList at:addr];
    Address count = [self.file readUnsignedValueForFieldPath:@"count" at:addr];
    // define, dePAC, import, and analyze each protocol
    NSMutableArray *protocolNames = [[NSMutableArray alloc] init];
    Address curProtocolPtr = addr + sizeof(void *);
    for (int i = 0; i < count; i++) {
        // define type as a pointer, or something like it
        [self.file setType:Type_Int64 atVirtualAddress:curProtocolPtr forLength:8];
        
        NSString *name = [self analyzeProtocol:curProtocolPtr];
        [self.file setInlineComment:name atVirtualAddress:curProtocolPtr reason:CCReason_User];
        [protocolNames addObject:name];
        curProtocolPtr += sizeof(void *);
    }
    return protocolNames;
}

- (void)analyzeCurrentAddressAsObjcClass:(id)sender {
    _document = [self.services currentDocument];
    _file = [self.document disassembledFile];
    // save navigation stack pointer to later restore it
    Address stackPtrBefore = [self.document navigationStackPointer];
    [self.document beginToWait:@"Please standby..."];
    
    [self analyzeAddressAsObjcClass:[self.document currentAddress] isMeta:false];
    
    // reset navigation stack to before
    [self.document popNavigationStackToIndex:stackPtrBefore];
    
    [self.document updateUI];
    [self.document waitForBackgroundProcessToEnd];
    [self.document endWaiting];
}

- (void)analyzeCurrentAddressAsObjcProto:(id)sender {
    _document = [self.services currentDocument];
    _file = [self.document disassembledFile];
    // save navigation stack pointer to later restore it
    Address stackPtrBefore = [self.document navigationStackPointer];
    [self.document beginToWait:@"Please standby..."];
    
    [self analyzeProtocol:[self.document currentAddress]];
    
    [self.document popNavigationStackToIndex:stackPtrBefore];
    
    [self.document updateUI];
    [self.document waitForBackgroundProcessToEnd];
    [self.document endWaiting];
}

-(void)analyzeAllClasses:(id)sender {
    _document = [self.services currentDocument];
    _file = [self.document disassembledFile];
    Address stackPtrBefore = [self.document navigationStackPointer];
    [self.document beginToWait:@"Please standby..."];
    
    // for class in _classlist
    NSObject<HPSection> *classList = [self.file sectionNamed:@"__objc_classlist"];
    for (Address cur = [classList startAddress]; cur < [classList endAddress]; cur += sizeof(void *)) {
        @try {
            [self analyzeAddressAsObjcClass:cur isMeta:false];
        } @catch (NSException *exception) {
            [self.document logErrorStringMessage:[NSString stringWithFormat:@"Error analyzing classlist at %#llx", cur]];
        }
    }
    // reset navigation stack to before
    [self.document popNavigationStackToIndex:stackPtrBefore];
    [self.document updateUI];
    [self.document waitForBackgroundProcessToEnd];
    [self.document endWaiting];
}

-(void)analyzeAllProtocols:(id)sender {
    _document = [self.services currentDocument];
    _file = [self.document disassembledFile];
    
    Address stackPtrBefore = [self.document navigationStackPointer];
    
    [self.document beginToWait:@"Please standby..."];
    // for proto in protolist
    NSObject<HPSection> *protoList = [self.file sectionNamed:@"__objc_protolist"];
    for (Address cur = [protoList startAddress]; cur < [protoList endAddress]; cur += sizeof(void *)) {
        @try {
            [self analyzeProtocol:cur];
        } @catch (NSException *exception) {
            [self.document logErrorStringMessage:[NSString stringWithFormat:@"Error analyzing protolist at %#llx", cur]];
        }
    }
    // for proto in __protorefs
    [self.document popNavigationStackToIndex:stackPtrBefore];
    [self.document updateUI];
    [self.document waitForBackgroundProcessToEnd];
    [self.document endWaiting];
}

@end
