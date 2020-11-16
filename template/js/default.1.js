window.onmousemove = function(e) {
    if (!window.REGTICK) {
	window.requestAnimationFrame(function() {
	    var x = e.clientX || e.left, y = e.clientY || e.top;
	    window.REGIONS = (window.REGIONS || []).filter(function(rect) { return rect.valid; })
	    window.REGIONS.forEach(function(rect) {
		var inside = false, margin = 5;
		rect.boxes.forEach(function(el) {
		    var box = el.getBoundingClientRect();
		    inside = inside || (
			x >= box.left - margin &&
			    x <= box.right + margin &&
			    y >= box.top - margin &&
			    y <= box.bottom + margin);
		})
		if (!inside) {
		    try {
			rect.callback(x, y);
		    } catch(e) {
			console.log(e)
		    }
		    rect.valid = false;
		}
	    })
	    window.REGTICK = false;
	});
	window.REGTICK = true;
    }
}

window.ontouchend = function(e) {
    var el = e.changedTouches[0];
    if (el) window.onmousemove(el);
}

function isString(a) {
    return (Object.prototype.toString.call(a) === '[object String]');
}

function $html() {
    var lastInputId;
    var camel = function(e) {
	return e.replace(/([A-Z])/g, function(u){return "-"+u.toLowerCase()})
    }
    var w = function(args) {
	var div = document.createElement("div"), h = '';
	for (var i in args) {
	    var a = args[i];
	    if (isString(a)) {
		h += a + ' '
	    } else {
		var el = document.createElement(a.tag);
		if (a.tag == 'button') el.setAttribute('class', 'gbutton');

		var _append = function(a) {
		    if (isString(a)) {
			el.appendChild(document.createTextNode(a));
		    } else if (Object.prototype.toString.call(a) === '[object Array]') {
			for (var i in a) _append(w([ a[i] ]));
		    } else {
			el.appendChild(a.tagName ? a : w([a]));
		    }
		}
		for (var k in a) {
		    if (k === 'tag') continue;
		    if (k === 'style') {
			var style = '';
			for (var name in a[k])
			    style += camel(name) + ':' + a[k][name] + ';';
			el.setAttribute("style", style);
		    } else if (k === "checked" || k === "selected" || k === 'readonly') {
			a[k] ? el.setAttribute(k, k) : 0;
		    } else if (k === "children") {
			_append(a[k]);
		    } else {
			el.setAttribute(camel(k), isString(a[k]) ? a[k].replace('$last-input-id', lastInputId) : a[k]);
		    }
		}
		if (el.tagName == 'INPUT' && !el.id) {
		    lastInputId = btoa('' + Math.random()).replace('=', '');
		    el.id = lastInputId;
		}
		h += el.outerHTML;
	    }
	}
	div.innerHTML = h;
	return div.firstElementChild
    }
    return w(arguments);
}

function $value(el) {
    return el && el.getAttribute && el.getAttribute("value")
}

function $wait(el, p) {
    var el = $(el), stopped = false, oldHTML = el.html();
    el.html('<div class="spinner-border spinner-border-sm" role="status"></div>');
    el.attr("disabled", "disabled");
    if (p) {
        var div = $("<div>").css('margin-left', '0.5em');
        el.append(div);
        el.find('div').css('display', 'inline-block')
        p(function(text) {
            if (stopped) return false; 
            div.text(text);
        })
    }
    return function() {
        if (stopped) return;
        stopped = true;
        el.removeAttr("disabled");
        el.html(oldHTML);
    }
}

function $dialog(title, desc, yes) {
    var btn = $("<button>").addClass('btn btn-primary').text('确定');
    var m = $("<div>").addClass('modal')
        .append($("<div>").addClass('modal-dialog')
            .append($("<div>").addClass('modal-content')
                .append($("<div>").addClass('modal-header').text(title ? title : location.title))
                .append($("<div>").addClass('modal-body')
                    .append(typeof desc === 'string' ? $("<p>").text(desc) : desc))
                .append($("<div>").addClass('modal-footer')
                    .append(btn))))
    btn.on('click', function() { m.modal('hide') })
    $(".container").first().append(m);
    m.modal({ show: true }).on("hidden.bs.modal", function() { m.remove() })
    return false
}

function $input(title, desc, defaultValue, yes) {
    var content = $("<div>").addClass('modal-body'), inputs = [];
    if (desc) {
        content = content.append($("<p>").text(desc))
    }
    if (defaultValue !== null) {
        if (!$.isArray(defaultValue)) defaultValue = [{value: defaultValue}];
        defaultValue.forEach(function(v) {
            var input = typeof v.value === 'string' ?
                $("<input>").val(v.value).addClass('form-control').attr('placeholder', v.text) :
                $(v.value);
            if (v.password) input = input.attr('type', 'password')
            if (v.checkbox) {
                var id = 's' + Math.random()
                input = $("<div>").addClass('form-group form-check')
                    .append($("<input>").attr('id', id).attr('type', 'checkbox').addClass('form-check-input'))
                    .append($("<label>").attr('for', id).text(v.value).addClass('form-check-label'))
            }
            content = content.append($("<div>").addClass('form-group').append(input))
            inputs.push(v.checkbox ? input.find('input') : input)
        })
        inputs.forEach(function(i) { i.OTHERS = inputs, i.get(0).OTHERS = inputs })
    }
    inputs.yes = $("<button>").addClass('btn btn-primary').text('确定');
    inputs.no = $("<button>").addClass('btn btn-secondary').text('取消');
    var m = $("<div>").addClass('modal')
        .append($("<div>").addClass('modal-dialog')
            .append($("<div>").addClass('modal-content')
                .append($("<div>").addClass('modal-header').text(title))
                .append($("<div>").addClass('modal-body').append(content))
                .append($("<div>").addClass('modal-footer')
                    .append(inputs.yes)
                    .append(inputs.no))))
    inputs.no.on('click', function() { m.modal('hide') })
    inputs.yes.on('click', function() { if (yes(inputs) === false) return; m.modal('hide') });
    inputs.yes.dialog = m;
    $(".container").first().append(m);
    m.modal('show').on("hidden.bs.modal", function() { m.remove() })
}

function $post(lockElement, url, data, reload) { 
    var m = document.cookie.match(/(^| )id=([^;]+)/);
    data = data || {}
    data.api = "1"
    data.api2_uid = m ? m[2] : "";

    var xhr = $.post(url, data);
    if (lockElement) {
        var stop = $wait(lockElement);
        xhr = xhr.always(function() {
            console.log(lockElement, "unlock")
            stop();
        })
    }
    if (reload) {
        xhr = xhr.done(function(r) {
            if (r === 'ok') {
                location.reload();
                return;
            }
            $dialog('错误', __i18n(r))
        }).fail(function(r) {
            console.log(xhr)
            $dialog('错误', '网络错误')
        })
    }
    xhr.closeInput = function() {
        return xhr.done(function(r) {
            r === 'ok' ? lockElement.dialog.modal('hide') : $dialog('错误', __i18n(r));
        }).fail(function(r) {
            $dialog('错误', '网络错误')
        })
    }
    return xhr;
}

(function addXhrProgressEvent($) {
    var originalXhr = $.ajaxSettings.xhr;
    $.ajaxSetup({
        progress: function() { },
        xhr: function() {
            var req = originalXhr(), that = this;
            if (req) {
                if (req.upload.addEventListener) {
                    req.upload.addEventListener("progress", function(evt) {
                        that.progress(evt);
                    }, true);
                }
            }
            return req;
        }
    });
})(jQuery);

function $uploadImage(el, file, yes) {
    var fake = false, work = function(file) {
        var fd = new FormData()
        fd.append('i', file);
        var updater, stop = $wait(el, function(u) { updater = function(t) { u(t + '%') } });
        $.ajax({
            url: '/api/upload_image',
            type: 'post',
            data: fd,
            contentType: false,
            processData: false,
            success: function(id, x, r) {
                stop();
                if (!id.match(/^LOCAL:/)) {
                    $dialog(null, '上传图片失败: ' + id);
                    return;
                }
                yes({
                    id: id, size: file.size, type: file.type, name: file.name,
                    url: r.getResponseHeader('X-Media'), thumb: r.getResponseHeader('X-Media-Thumb'),
                })
            },
            error: function(r) {
                $dialog(null, '上传图片失败: ' + r.responseText);
                stop();
            },
            progress: function(evt) {
                var p = evt.loaded / evt.total;
                updater(parseInt(p * 70));
                if (p > 0.99 && !fake) {
                    fake = true;
                    var x = 70, h = setInterval(function() {
                        x += (100 - x) * Math.random() / 1.5;
                        if (updater(parseInt(x)) === false) clearInterval(h);
                    }, 800)
                }
            }
        })
    }

    if (file) {
        work(file);
        return;
    }
    $('.image-hidden-selector').remove();
    var input = $("<input>").addClass('image-hidden-selector').attr('type', 'file').css('display', 'none')
    input.off('change').on('change', function() {
        var files = input[0].files;
        if (!files.length) return;
        work(files[0]);
        input.remove();
    }) 
    $('body').append(input);
    input.click();
}

function loadKimochi(el) {
    var ul = el.querySelector('ul');
    if (ul.childNodes.length) return;

    for (var i = 0; i <= 44; i++) {
        var li = $html({tag:'li'}), a = $html({tag:'a'}), img = $html({tag:'img'});
        img.src = '/s/emoji/emoji' + i + '.png';
        if (i == 0) {
            img.className = 'kimochi-selector';
            img.setAttribute("kimochi", "0");
        }
        a.appendChild(img);
        a.onclick = (function(i, img) {
            return function() {
                img.src = '/s/assets/spinner2.gif';
                $post('/api/user_kimochi', {k: i}, function(resp) {
                    if (resp === 'ok')  location.reload(); 
                });
            }
        })(i, img)
        li.appendChild(a);
        ul.appendChild(li);
    }
}

function isInViewport(el, scale) {
    var top = el.offsetTop, height = el.offsetHeight, h = window.innerHeight, s = scale || 0;
    while (el.offsetParent) {
        el = el.offsetParent;
        top += el.offsetTop;
    }
    return top < (window.pageYOffset + h + h*s) && (top + height) > window.pageYOffset - h*s;
} 

function likeArticle(el, id) {
    var v = el.getAttribute("liked") === "true" ? "" : "1",
        num = el.querySelector('span.num'),
        icon = el.querySelector('i');
    var stop = $wait(num);
    $post("/api2/like_article", {like:(v || ""), to:id}, function(res) {
        stop();
        if (res !== "ok") return res;
        if (v) {
            el.setAttribute("liked", "true")
            icon.className = 'icon-heart-filled';
            num.innerText = (parseInt(num.innerText) || 0) + 1;
        } else {
            el.setAttribute("liked", "false")
            icon.className = 'icon-heart-2';
            num.innerText = parseInt(num.innerText) ? (parseInt(num.innerText) - 1) : 0;
        }
    }, stop);
}

function deleteArticle(el, id) {
    if (!confirm("是否确认删除该发言？该操作不可逆")) return;
    var stop = $wait(el);
    $post("/api2/delete", { id: id }, function (res) {
        stop();
        if (res != "ok") return res;
        $q("[data-id='" + id + "'] > pre", true).forEach(function(e) {
            e.innerHTML = "<span class=deleted></span>";
        });
        $q("[data-id='" + id + "'] .media img", true).forEach(function(e) {
            e.src = '';
        });
        $q("[data-id='" + id + "'] .media", true).forEach(function(e) {
            e.style.display = 'none';
        });
    }, stop)
}

function nsfwArticle(el, id) {
    var stop = $wait(el);
    $post("/api2/toggle_nsfw", { id: id }, function (res) {
        stop();
        if (res != "ok") return res;
        el.setAttribute("value", !($value(el) === 'true'))
        return "ok";
    }, stop);
}

function dropTopArticle(el, id) {
    if (!confirm("是否取消置顶")) return;
    $postReload(el, "/api2/drop_top", { id: id, extra: "" })
}

function lockArticle(el, id) {
    var div = $html({
	tag: 'div',
	style: {position:'absolute', boxShadow: '0 1px 5px rgba(0,0,0,.3)'},
	class: 'tmpl-light-bg'
    }), box = el.getBoundingClientRect(),
        bodyBox = document.body.getBoundingClientRect(),
        currentValue = $value(el),
        reg = {};

    div.style.left = box.left - bodyBox.left + "px";
    div.style.top = box.bottom - bodyBox.top + "px";

    var checkbox = function(i, t) {
	return $html({
	    tag: "div",
	    style: {margin: "0.5em"},
	    children: [
		{
		    tag: 'input',
		    value: i,
		    type: "radio",
		    name: "reply-lock",
		    class: "icon-input-checkbox",
		    checked: i == currentValue
		}, 
		{tag: 'i', class: "icon-ok-circled2"},
		{tag: 'label', for: '$last-input-id', children: t}
	    ]
	})
    }
    div.appendChild(checkbox(0, "不限制回复"))
    div.appendChild(checkbox(1, "禁止回复"))
    div.appendChild(checkbox(2, "我关注的人可回复"))
    div.appendChild(checkbox(3, "我关注的人和被@的人可回复"))
    div.appendChild(checkbox(4, "我关注的人和我粉丝可回复"))
    document.body.appendChild(div)

    if (id) div.appendChild($html({
	tag: 'div',
	style: {margin: '0.5em', textAlign: 'center'},
	children: {tag: 'button', children: '更新设置'}
    }))

    reg = { valid: true, boxes: [el, div], callback: function(x, y) {
        if (!id) {
            var v = (div.querySelector("[name=reply-lock]:checked") || {}).value;
            if (v) el.setAttribute("value", v)
        }
        div.parentNode.removeChild(div);
    }, };
    window.REGIONS = window.REGIONS || [];
    window.REGIONS.push(reg);

    if (!id) return;
    div.querySelector('button').onclick = function(e) {
        var stop = $wait(e.target), v = div.querySelector("[name=reply-lock]:checked").value;
        $post("/api2/toggle_lock", { id: id, mode: v }, function (res) {
            stop();
            if (res != "ok") return res;
            el.setAttribute("value", v)
            el.innerHTML = $html({
		tag: 'i', class: v > 0 ? "tmpl-normal-text icon-lock" : "tmpl-light-text icon-lock-open"
	    }).outerHTML;
            return "ok:回复设置更新"
        }, stop);
    }
}

function followBlock(el, m, id) {
    if (m == "block" && $value(el) === "false") {
        if (window.localStorage.getItem('not-first-block') != 'true') {
            if (!confirm("是否确定拉黑" + id)) {
                return;
            }
            window.localStorage.setItem('not-first-block', 'true')
        }
    }
    var stop = $wait(el), obj = { method: m };
    id = id || el.getAttribute("user-id");
    obj[m] = $value(el) === "true" ? "" : "1";
    obj['to'] = id;
    $post("/api2/follow_block", obj, function(res, x) {
        stop();
        if (res != "ok") return res;

	var on = obj[m] != "";
	el.setAttribute("value", on ? "true" : "false");
        if (m == "follow") {
            el.innerHTML = $html({tag:'i',class: on ? "icon-heart-broken" : "icon-user-plus"}).outerHTML;
	    if (x.getResponseHeader("X-Follow-Apply") && on)
		return "ok:已关注, 等待批准";
            return "ok:" + (on ? "已关注" : "已取消关注") + id;
        } else if (m == "accept") {
            el.innerHTML = $html({tag:'i',class: "icon-ok tmpl-green-text" }).outerHTML;
	    return "ok" 
        } else {
            el = el.querySelector('i');
            el.className = el.className.replace(/block-\S+/, '') + " block-" + on;
            el = el.nextElementSibling;
            if (el) el.innerText = on ? "解除" : "拉黑";
            return "ok:" + (on ? "已拉黑" + id : "已解除" + id + "拉黑状态")
        }
    }, stop)
}

function __i18n(t) {
    if (t === 'ok')
        return "成功"
    if (t.match(/cooldown`([0-9\.]+)s/)) 
        return "请等待" + t.split("`").pop();
    if (t === "captcha_failed")
        return "无效验证码";
    if (t === "expired_session")
        return "Token过期，请重试";
    if (t === "content_too_short")
        return "正文过短";
    if (t === "cannot_reply")
        return "无法回复";
    if (t === "internal_error")
        return "服务端异常";
    if (t === "user_not_found")
        return "无权限";
    if (t === "user_not_found_by_id")
        return "ID不存在";
    if (t === "new_password_too_short")
        return "新密码太短";
    if (t === "old_password_invalid")
        return "旧密码不符";
    if (t === "duplicated_id")
        return "ID已存在";
    if (t === "duplicated_email")
        return "Email已存在";
    if (t === "id_too_short")
        return "无效ID";
    if (t === "invalid_id_password")
        return "无效ID或密码";
    if (t === "user_not_permitted")
        return "无权限";
    if (t === "cannot_follow")
        return "无法关注";
    if (t === "cannot_block_tag")
        return "无法拉黑标签";
    return t;
}

function loadMore(tlid, el, data) {
    data.cursors = $value(el);
    var stop = $wait(el);
    $post('/api/timeline', data, function(pl) {
        stop();
        if (pl.EOT) {
            el.innerText = "没有更多内容了";
            el.setAttribute("eot", "true");
            el.className += " tmpl-light-text";
            el.onclick = function() { location.reload() }
        } else {
            el.innerText = "更多...";
        }
        if (pl.Articles) {
            el.setAttribute("value", pl.Next);
            pl.Articles.forEach(function(a) {
                var dedup = $q('#' + tlid + " > [data-id='" + a[0] + "']");
                if (dedup && dedup.length) {
                    console.log("dedup:", a[0])
                    return;
                }
                var div = document.createElement("div");
                div.innerHTML = a[1];
                $q('#' + tlid).appendChild(div.querySelector("div"));
            })
        }
        expandNSFW();
        if (!data.reply)
            history.pushState("", "", location.pathname + location.search)
    }, stop);
    //   console.log(document.documentElement.scrollTop);
}

function preLoadMore(tlid, nextBtn) {
    window.addEventListener('scroll', function(e) {
        if (!window.ticking) {
            window.requestAnimationFrame(function() {
                $q("#" + tlid + " > .row", true).forEach(function(c) {
                    if (isInViewport(c, 3)) {
                        if (c.childNodes.length == 0) {
                            c.innerHTML = c.__html;
                            c.style.height = "";
                        }
                    } else {
                        if (c.childNodes.length) {
                            c.style.height = c.offsetHeight + "px";
                            c.__html = c.innerHTML;
                            c.innerHTML = "";
                        }
                    }
                })
                if (isInViewport(nextBtn) &&
                    !nextBtn.getAttribute("disabled") && nextBtn.getAttribute("eot") !== "true") {
                    console.log("Load next");
                    nextBtn.click();
                }
                window.ticking = false;
            });
            window.ticking = true;
        }
    });
}

// Nested replies view
function showReply(aid, closeToHome, shortid) {
    // We have something popped up already, wait them to be removed first
    if (window.REGIONS && window.REGIONS.length) return;

    // User selected some texts on the page, so we won't pop up
    if (window.getSelection && window.getSelection().type == 'Range') return;

    $q(".image-uploader.dropzone", true).forEach(function(el) { el.UPLOADER ? el.UPLOADER.removeAllFiles() :0})

    // Close duplicated windows before opening a new one
    $q("[data-parent='" + aid + "']", true).forEach(function(e) { e.CLOSER.click(); });

    var div = $html({
	tag: 'div',
	id: 'Z' + Math.random().toString(36).substr(2, 5),
	class: 'div-inner-reply tmpl-body-bg',
	style: {
	    position: 'fixed',
	    left: '0',
	    top: '0',
	    width: '100%',
	    height: '100%',
	    overflowY: 'scroll',
	    overflowX: 'hidden'
	},
	dataParent: aid
    }), divclose = $html({
	tag: 'div',
	style: {
	    margin: '0 auto',
	    backgroundImage: 'url(/s/assets/spinner.gif)',
	    backgroundRepeat: 'no-repeat',
	    backgroundPosition: 'center center'
	},
	class: 'container rows replies',
	children: {
	    tag: 'div',
	    class: 'row',
	    style: {padding: '0.5em', lineHeight: '30px', display: 'flex'},
	    children: [
		{tag: 'i', class: 'control icon-left-small'},
		{
		    tag: 'input',
		    style: {
			margin:'0 0.5em',
			width:'100%',
			textAlign: 'center',
			border:'none',
			background:'transparent',
			cursor:'pointer'
		    },
		    value: location.protocol + "//" + location.host + "/" + (shortid ? shortid : "S/" + aid.substring(1)),
		    readonly: true,
		    onclick: 'this.select();document.execCommand("copy");$popup("已复制")'
		},
		{tag: 'i', class: 'control icon-link', onclick: "this.previousElementSibling.click()"},
	    ]
	}
    })

    div.CLOSER = divclose.querySelector('.icon-left-small')
    div.CLOSER.onclick = function() {
        if (closeToHome) { location.href = "/t"; return }

        div.parentNode.removeChild(div)
        if ($q('[data-parent]', true).length === 0) {
            history.pushState("", "", window.ORI_HERF);
            document.body.style.overflow = null;
        }
    }
    divclose.insertBefore($q("nav", true)[0].cloneNode(true), divclose.firstChild);

    div.appendChild(divclose);
    document.body.appendChild(div);
    document.body.style.overflow = 'hidden';

    $post('/api/p/' + aid, {}, function(h) {
        div.innerHTML = h;
        div.style.backgroundImage = null;
        var rows = div.querySelector('.rows'),
            box = div.querySelector(".reply-table textarea"),
            uploader = div.querySelector(".reply-table .image-uploader");

        if (box) window.TRIBUTER.attach(box);
        if (uploader) attachImageUploader(uploader);

        rows.insertBefore(divclose.querySelector('.row'), rows.firstChild);
        rows.insertBefore($q("nav", true)[0].cloneNode(true), rows.firstChild);
    });

    if (!location.href.match(/\?pid=/)) window.ORI_HERF = location.href;
    history.pushState("", "", location.pathname + "?pid=" + encodeURIComponent(aid) + location.hash + "#" + div.id)
}

window.onpopstate = function(event) {
    var closes = $q(".div-inner-reply", true)
    location.href.split("#").forEach(function(id) {
        closes = closes.filter(function(c) { return c.id != id })
    })
    closes.forEach(function(c) { c.CLOSER.click() })
};

function updateSetting(el, field, value, cb, errcb) {
    var data = {},
        stop = $wait(el.tagName === 'INPUT' && el.className == "icon-input-checkbox" ?
            el.nextElementSibling.nextElementSibling: el);
    data["set-" + field] = "1";
    if (field !== 'bio') {
        data[field] = value;
    } else {
        ["description"].forEach(function(id) { data[id] = $q("[name='" + id + "']").value })
    }
    $post("/api/user_settings", data, function(h, h2) {
        stop();
        if (cb) cb(h, h2);
        return h
    }, function() {
        stop();
        if (errcb) errcb();
    })
}

function showInfoBox(el, uid) {
    if (uid.substr(0,1) == "?") return;
    if (el.BLOCK) return;
    el.BLOCK = true;

    var div = $q("<div>"),
        loading = $html("<div style='position:absolute;left:0;top:0;width:100%;height:100%'></div>"),
        bodyBox = document.body.getBoundingClientRect(),
        box = el.getBoundingClientRect(),
        boxTopOffset = 0,
        addtionalBoxes = [],
        startAt = new Date().getTime();

    div.className = 'user-info-box';
    div.innerHTML = window.DUMMY_USER_HTML;
    div.querySelector('img.avatar').src = el.src || '';
    div.querySelector('img.avatar').onclick = null;

    if (el.className === 'mentioned-user') {
        div.querySelector('span.post-author').innerHTML = el.innerHTML;
    } else {
        for (var x = el.parentNode; x ; x = x.parentNode) {
            var pa = x.querySelector('span.post-author')
            if (pa) {
                div.querySelector('span.post-author').innerHTML = pa.innerHTML;
                break;
            }
        }
    }

    for (var x = el; x ; x = x.parentNode) {
        if (x.getAttribute('data-id') || x.className === 'mentioned-user') {
            box = x.getBoundingClientRect();
            if (x.className === 'mentioned-user') {
                addtionalBoxes.push(x);
                boxTopOffset = box.bottom - box.top;
            }
            break;
        }
    }

    div.style.position = 'absolute';
    div.style.left = box.left - bodyBox.left + 'px';
    div.style.top = box.top - bodyBox.top + boxTopOffset + 'px';
    div.style.boxShadow = "0 1px 2px rgba(0, 0, 0, .3)";
    document.body.appendChild(div);

    var reg = {
        valid: true,
        boxes: [div].concat(addtionalBoxes),
        callback: function(x, y) {
            div.parentNode.removeChild(div);
            el.BLOCK = false;
        },
    };

    window.REGIONS = window.REGIONS || [];
    window.REGIONS.push(reg);

    var adjustDiv = function() {
	var newBox = div.getBoundingClientRect();
	if (newBox.right > bodyBox.right) {
	    div.style.left = '0';
	    div.style.right = "0";
	}
    }
    $post("/api/u/" + encodeURIComponent(uid), {}, function(h) {
        if (h.indexOf("ok:") > -1) {
            setTimeout(function() {
                div.innerHTML = h.substring(3)
		adjustDiv();
            }, new Date().getTime() - startAt > 100 ? 0 : 100)
            return
        }
        return h
    }, function() {
	adjustDiv();
        el.BLOCK = false;
    })
}

function adjustImage(img) {
    var ratio = img.width / img.height,
        div = img.parentNode.parentNode,
        note = div.querySelector('.long-image'),
        r = div.getBoundingClientRect(),
        smallimg = false;

    if (ratio < 0.33 || ratio > 3) {
        div.style.backgroundSize = 'contain';
        note.style.display = 'block';
    } else {
        div.style.backgroundSize = 'cover';
    }

    if (img.width <= r.width * 0.9 && img.height <= r.height * 0.9) {
        div.style.backgroundSize = 'auto';
        smallimg = true;
    }

    if (img.src.match(/\.gif$/)) {
        note.style.display = 'block';
        note.innerText = 'GIF';
    }

    if (div.hasAttribute("enlarge")) {
        // Raw image and its thumbnail may have different w/h ratios, so recalc is needed
        // div.style.height = div.getBoundingClientRect().width / ratio + "px";
        // if (smallimg) div.style.height = img.height + "px";
        div.style.height = window.innerHeight + "px";
        div.scrollIntoView();
        div.style.backgroundSize = 'contain';
    }

    div.style.backgroundImage = 'url(' + img.src + ')';
    div.onclick = function() {
        if (!div.hasAttribute("enlarge")) {
            div.setAttribute("enlarge", "enlarge")
            div.style.width = "100%";
            div.style.height = window.innerHeight + "px";
            div.style.borderRadius = '0';
            div.scrollIntoView();

            var imgload = new Image(), imgprogress = new Image(), divC = $q("<div>"), loaded = false;

            imgload.src = img.src.replace(/\/thumb\//, '/');
            imgload.onload = function() {
                loaded = true;
                img.src = imgload.src; // trigger adjustImage() again
                try { div.removeChild(divC) } catch (e) {}
            }

            imgprogress.src =  '/s/assets/spinner.gif';
            imgprogress.setAttribute('style', 'opacity:unset;display:block;position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);');
            divC.className = 'image-loading-div';
            divC.appendChild(imgprogress);
            div.appendChild(divC);

            setTimeout(function() { if (!loaded) divC.style.opacity = '1' }, 100)
        } else {
            div.removeAttribute("enlarge")
            div.style.borderRadius = null;
            div.style.width = null;
            div.style.height = null;
	    div.parentNode.querySelector('[image-index="0"]').scrollIntoView();
        }
    }
}

function adjustVideoIFrame(el, src) {
    el.style.display = 'none';
    el.previousElementSibling.style.display = 'none';
    el = el.nextSibling;
    el.style.display = null;
    var box = el.getBoundingClientRect();
    var w = box.right - box.left;
    el.style.height = (el.getAttribute("fixed-height") || (w*0.75)) + 'px';
    el.src = src;
}

function isDarkMode() {
    return (document.cookie.match(/(^| )mode=([^;]+)/) || [])[2] === 'dark';
}

function attachImageUploader(el) {
    if (el.hasAttribute("uploader")) return;

    el.UPLOADER = new Dropzone(el, {
        url: "/api/upload_image",
        maxFilesize: 16,
        maxFilesize: 5,
        addRemoveLinks: true,
        dictRemoveFile: "删除",
        dictFileTooBig: "文件过大 {{filesize}}M, Max: {{maxFilesize}}M",
        dictCancelUpload: "取消",
    }).on("success", function(f, id) {
        var m = id.match(/^CHECK\((.+)\)-(.+)/);
        if (m && m.length == 3) {
            var stop = $wait(f._removeLink.parentNode.querySelector('.dz-success-mark'));
            var h = setInterval(function() {
                console.log("large check:", m[1])
                var img = new Image();
                img.onload = function() { clearInterval(h); stop(); }
                img.src = m[1];
            }, 1500)
            id = m[2]
        }
        f._removeLink.setAttribute('data-uri', id);
    });

    el.setAttribute("uploader", "true");
}

function createAvatar(id) {
    var randseed = new Array(4); // Xorshift: [x, y, z, w] 32 bit values

    function seedrand(seed) {
        randseed.fill(0);

        for(let i = 0; i < seed.length; i++) {
            randseed[i%4] = ((randseed[i%4] << 5) - randseed[i%4]) + seed.charCodeAt(i);
        }
    }

    function rand() {
        // based on Java's String.hashCode(), expanded to 4 32bit values
        const t = randseed[0] ^ (randseed[0] << 11);

        randseed[0] = randseed[1];
        randseed[1] = randseed[2];
        randseed[2] = randseed[3];
        randseed[3] = (randseed[3] ^ (randseed[3] >> 19) ^ t ^ (t >> 8));

        return (randseed[3] >>> 0) / ((1 << 31) >>> 0);
    }

    function createColor() {
        //saturation is the whole color spectrum
        const h = Math.floor(rand() * 360);
        //saturation goes from 40 to 100, it avoids greyish colors
        const s = ((rand() * 40) + 30) + '%';
        //lightness can be anything from 0 to 100, but probabilities are a bell curve around 50%
        const l = ((rand() + rand() + rand() + rand()) * 25) + '%';

        return 'hsl(' + h + ',' + s + ',' + l + ')';
    }

    function createImageData(size) {
        const width = size; // Only support square icons for now
        const height = size;

        const dataWidth = Math.ceil(width / 2);
        const mirrorWidth = width - dataWidth;

        const data = [];
        for(let y = 0; y < height; y++) {
            let row = [];
            for(let x = 0; x < dataWidth; x++) {
                // this makes foreground and background color to have a 43% (1/2.3) probability
                // spot color has 13% chance
                row[x] = Math.floor(rand()*2.3);
            }
            const r = row.slice(0, mirrorWidth);
            r.reverse();
            row = row.concat(r);

            for(let i = 0; i < row.length; i++) {
                data.push(row[i]);
            }
        }

        return data;
    }

    function buildOpts(opts) {
        const newOpts = {};

        newOpts.seed = opts.seed || Math.floor((Math.random()*Math.pow(10,16))).toString(16);

        seedrand(newOpts.seed);

        newOpts.size = opts.size || 8;
        newOpts.scale = opts.scale || 4;
        newOpts.color = opts.color || createColor();
        newOpts.bgcolor = opts.bgcolor || createColor();
        newOpts.spotcolor = opts.spotcolor || createColor();

        return newOpts;
    }

    function renderIcon(opts, canvas) {
        opts = buildOpts(opts || {});
        const imageData = createImageData(opts.size);
        const width = Math.sqrt(imageData.length);

        canvas.width = canvas.height = opts.size * opts.scale;

        const cc = canvas.getContext('2d');
        cc.fillStyle = opts.bgcolor;
        cc.fillRect(0, 0, canvas.width, canvas.height);
        cc.fillStyle = opts.color;

        for(let i = 0; i < imageData.length; i++) {

            // if data is 0, leave the background
            if(imageData[i]) {
                const row = Math.floor(i / width);
                const col = i % width;

                // if data is 2, choose spot color, if 1 choose foreground
                cc.fillStyle = (imageData[i] == 1) ? opts.color : opts.spotcolor;

                cc.fillRect(col * opts.scale, row * opts.scale, opts.scale, opts.scale);
            }
        }

        return canvas;
    }


    var canvas = document.createElement('canvas');
    renderIcon({bgcolor: "#fafbfc", seed: id, size: 5, scale: 10}, canvas);
    return canvas;
}

function selectAvatar(el, throt) {
    if (!el.value) return;
    var reader = new FileReader();
    reader.readAsDataURL(el.files[0]);
    reader.onload = function () {
        var img = new Image();
        img.onerror = function() { $dialog(null, "加载头像失败") }
        img.onload = function() {
            img.onload = null;
            var canvas = document.createElement("canvas"), f = 1,
                success = function() {
                    console.log((img.src.length / 1.33 / 1024).toFixed(0) + "KB", f);
                    $("#img-" + el.id).attr("src", img.src);
                };

            if (img.src.length > throt) {
                var ctx = canvas.getContext("2d");
                canvas.width = img.width; canvas.height = img.height;
                ctx.drawImage(img,0,0);
                for (f = 0.8; f > 0; f -= 0.2) {
                    var res = canvas.toDataURL("image/jpeg", f);
                    if (res.length <= throt) {
                        img.src = res;
                        success();
                        return;
                    }
                }
                img.onerror();
            } else {
                success();
            }
        }
        img.src = reader.result;
    };
}
