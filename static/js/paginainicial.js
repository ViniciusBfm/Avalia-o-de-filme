const pesquisarbtn = document.querySelector(".pequisar")
const pesquisarBox = document.querySelector(".pesquisar-box")
const headerInicial = document.querySelector(".header-button")
const headerLogo = document.querySelector(".navegacao")
const closePesquisar = document.querySelector(".close")

//barra de pesquisa no header
pesquisarbtn.addEventListener("click", ()=>{
    headerInicial.style.display = "none"
    headerLogo.style.display = "none"
    pesquisarBox.style.display = "flex"
})
closePesquisar.addEventListener("click", ()=>{
    headerInicial.style.display = "flex"
    headerLogo.style.display = "flex"
    pesquisarBox.style.display = "none"
})
//menu de login
document.addEventListener('DOMContentLoaded', function () {
    var loginbtn = document.querySelector(".loginbtn");
    var menu = document.querySelector(".login");

    loginbtn.addEventListener('click', function (event) {
        // Evita que o evento de clique se propague para o documento inteiro
        event.stopPropagation();

        // Alternar a visibilidade do menu
        if (menu.style.display === 'none' || menu.style.display === '') {
            menu.style.display = 'block';
        } else {
            menu.style.display = 'none';
        }
    });

    // Adiciona um ouvinte de evento de clique ao documento inteiro
    document.addEventListener("click", (event) => {
        // Verifica se o clique não ocorreu dentro do menu ou no botão do menu
        if (!menu.contains(event.target) && event.target !== loginbtn) {
            // Fecha o menu
            menu.style.display = "none";
        }
    });
});

//Adicionar filmes ou séries
document.addEventListener('DOMContentLoaded', function () {
    var addbtn = document.querySelector(".adicionarbtn");
    var menu2 = document.querySelector(".adicionarfilmeseries-container");

    addbtn.addEventListener('click', function (event) {
        // Evita que o evento de clique se propague para o documento inteiro
        event.stopPropagation();

        // Alternar a visibilidade do menu
        if (menu2.style.display === 'none' || menu2.style.display === '') {
            menu2.style.display = 'block';
        } else {
            menu2.style.display = 'none';
        }
    });

    // Adiciona um ouvinte de evento de clique ao documento inteiro
    document.addEventListener("click", (event) => {
        // Verifica se o clique não ocorreu dentro do menu ou no botão do menu
        if (!menu2.contains(event.target) && event.target !== addbtn) {
            // Fecha o menu
            menu2.style.display = "none";
        }
    });
});
//Selecionar arquivos
document.addEventListener('DOMContentLoaded', function () {
    var fileInput = document.getElementById('capa');
    var fileName = document.querySelector('.file-name');

    fileInput.addEventListener('change', function () {
        // Atualiza o texto da span file-name com o nome do arquivo selecionado
        fileName.textContent = fileInput.files[0].name;
    });
});
//ajustar a ultima linha para não ficar com espaçamento
function ajustarUltimaLinha() {
    var container = document.querySelector('.todosfilmes-container-box');
    var items = container.querySelectorAll('.filmes-box');
    var rows = Math.ceil(items.length / 2); // Assumindo 3 itens por linha

    var lastRowStartIndex = (rows - 1) * 2;
    for (var i = 0; i < items.length; i++) {
        if (i >= lastRowStartIndex) {
            items[i].classList.add('ultima-linha');
        }
    }
}
//Seletor para mudar o layout de recente ou mais avaliados
function classificar() {
    var select = document.getElementById("select-classificacao");
    var selectedValue = select.options[select.selectedIndex].value;

    var containerRecentes = document.querySelector(".todosfilmes-container-box");
    var containerAvaliados = document.querySelector(".todosfilmes-container-box-maisavaliados");

    if (selectedValue === "recentes") {
        containerRecentes.style.display = "flex";
        containerAvaliados.style.display = "none";
    } else if (selectedValue === "avaliados") {
        containerRecentes.style.display = "none";
        containerAvaliados.style.display = "flex";
    }
}

//Alterar senha
//Alterar senha box
const alterarSenhaBtn = document.querySelector(".alterarbtn")
const alterarSenhaBox = document.querySelector(".alterar-senha")

document.addEventListener('DOMContentLoaded', function () {
    alterarSenhaBtn.addEventListener('click', function (event) {
        // Evita que o evento de clique se propague para o documento inteiro
        event.stopPropagation();

        // Alternar a visibilidade do menu
        if (alterarSenhaBox.style.display === 'none' || alterarSenhaBox.style.display === '') {
            alterarSenhaBox.style.display = 'block';
        } else {
            alterarSenhaBox.style.display = 'none';
        }
    });

    // Adiciona um ouvinte de evento de clique ao documento inteiro
    document.addEventListener("click", (event) => {
        // Verifica se o clique não ocorreu dentro do menu ou no botão do menu
        if (!alterarSenhaBox.contains(event.target) && event.target !== alterarSenhaBtn) {
            // Fecha o menu
            alterarSenhaBox.style.display = "none";
        }
    });
});
//Mobile de alterar senha
const alterarbtnmobile = document.querySelector(".alterarbtn-mobile")
const mobilemanu = document.querySelector(".mobile")
document.addEventListener('DOMContentLoaded', function () {
    alterarbtnmobile.addEventListener('click', function (event) {
        // Evita que o evento de clique se propague para o documento inteiro
        event.stopPropagation();

        // Alternar a visibilidade do menu
        if (alterarSenhaBox.style.display === 'none' || alterarSenhaBox.style.display === '') {
            alterarSenhaBox.style.display = 'block';
            mobilemanu.style.display = 'none'
        } else {
            alterarSenhaBox.style.display = 'none';
        }
    });

    // Adiciona um ouvinte de evento de clique ao documento inteiro
    document.addEventListener("click", (event) => {
        // Verifica se o clique não ocorreu dentro do menu ou no botão do menu
        if (!alterarSenhaBox.contains(event.target) && event.target !== alterarbtnmobile) {
            // Fecha o menu
            alterarSenhaBox.style.display = "none";
        }
    });
});
//mobile de login
const loginbtnmobile = document.querySelector(".loginbtn-mobile")
document.addEventListener('DOMContentLoaded', function () {
    var menu3 = document.querySelector(".login");

    loginbtnmobile.addEventListener('click', function (event) {
        // Evita que o evento de clique se propague para o documento inteiro
        event.stopPropagation();

        // Alternar a visibilidade do menu
        if (menu3.style.display === 'none' || menu3.style.display === '') {
            mobilemanu.style.display = 'none'
            menu3.style.display = 'block';
        } else {
            menu3.style.display = 'none';
        }
    });

    // Adiciona um ouvinte de evento de clique ao documento inteiro
    document.addEventListener("click", (event) => {
        // Verifica se o clique não ocorreu dentro do menu ou no botão do menu
        if (!menu3.contains(event.target) && event.target !== loginbtnmobile) {
            // Fecha o menu
            menu3.style.display = "none";
        }
    });
});
const menubtn = document.querySelector(".menubtn");
const mobilebox = document.querySelector(".mobile");

document.addEventListener('DOMContentLoaded', function () {
    menubtn.addEventListener('click', function (event) {
        event.stopPropagation();
        toggleMenu();
    });

    document.addEventListener("click", (event) => {
        if (!mobilebox.contains(event.target) && event.target !== menubtn) {
            mobilebox.style.display = "none";
        }
    });

    window.addEventListener('resize', function () {
        if (window.innerWidth > 768) {
            mobilebox.style.display = "none";
        }
    });
});

function toggleMenu() {
    if (mobilebox.style.display === 'none' || mobilebox.style.display === '') {
        mobilebox.style.display = 'flex';
    } else {
        mobilebox.style.display = 'none';
    }
}


