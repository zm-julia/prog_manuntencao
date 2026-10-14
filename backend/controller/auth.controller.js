const Usuario = require('../models/Usuario')

const cryptoJs = require('crypto-js')
const CHAVE_SECRETA = 'segredo'

const logar = async(req,res)=>{
    const valores = req.body
    console.log(valores)

    if(!valores.email || !valores.senha){
        return res.status(400).json({message: 'Todos os campos são obrigatórios!'})
    }

    try{
        const usuario = await Usuario.findOne({where: {email: valores.email}})
        if(!usuario){
            return res.status(404).json({message: 'usuario não encontrado'})
        }
        
        const bytes = cryptoJs.AES.decrypt(usuario.senha,CHAVE_SECRETA)
        const senha = bytes.toString(cryptoJs.enc.Utf8)

        if(valores.senha !== senha){
            return res.status(401).json({message: 'senha inválida!! digite novamente'})
        }

        // token

        const tempoEmMs = 30 * 60 * 30 * 1000
        const tempoExpira = Date.now() + tempoEmMs

        const payload = {
            idUsuario: usuario.codUsuario,
            nome: usuario.nome,
            expiraEm: tempoExpira
        }

        const token = cryptoJs.AES.encrypt(JSON.stringify(payload),CHAVE_SECRETA).toString()

        res.status(200).json({message: 'logado com sucesso', nome: usuario.nome, token: token})
    }catch(err){
        console.error('Não foi possível logar o Usuário',err)
        res.status(500).json({message: 'Não foi possível logar o Usuário'})
    }
}

module.exports = {logar}