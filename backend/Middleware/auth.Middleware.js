const cryptoJs = require('crypto-js')
const CHAVE_SECRETA = 'segredo'  //deve ficar no arquivo .env

function authMiddleware(req,res,next){
    const token = req.headers['authorization']

    if(!token){
        return res.status(401).json({message: 'acesso negado, faça o login'})
    }

    console.log(token)

    try{
        const bytes  = cryptoJs.AES.decrypt(token, CHAVE_SECRETA)
        const dadosDescriptografados = bytes.toString(cryptoJs.enc.Utf8)

        if(!dadosDescriptografados){
            return res.status(403).json({message:'acesso proibido'})
        }

        const payload = JSON.parse(dadosDescriptografados)

        if(Date.now() > payload.expiraEm){
           return res.status(401).json({message: 'sessão expirada, faça o login novamente'})
        }

        req.usuario = payload

        next()
    }catch(err){
        console.error('falha na autenticação', err)
        return res.status(401).json({message: 'falha na autenticação'})
    }
}

module.exports = authMiddleware