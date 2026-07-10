#!/usr/bin/env python3
import csv,json,sys
import numpy as np
p=sys.argv[1] if len(sys.argv)>1 else 'tensor_v2_features.csv'
with open(p) as f:
 r=csv.reader(f); h=next(r); rows=list(r)
src=np.array([z[0] for z in rows]); sample=np.array([int(z[1]) for z in rows]); block=np.array([int(z[2]) for z in rows]); y=np.array([int(z[3]) for z in rows]); X=np.array([[float(q) for q in z[4:]] for z in rows])

def whiten(train,test):
 mu=train.mean(0); sd=train.std(0); keep=sd>1e-10
 return (train[:,keep]-mu[keep])/sd[keep],(test[:,keep]-mu[keep])/sd[keep]
def predict(labels, payload_block, alpha=100.):
 ix=np.where((src=='control')&(block==payload_block))[0]; xx=X[ix]; yy=labels.copy(); reps=sample[ix]//16; pred=np.empty(len(ix),int)
 for fold in np.unique(reps):
  tr=reps!=fold; te=~tr; a,b=whiten(xx[tr],xx[te]);
  # dual ridge multiclass; avoids any scalar marginal and uses the full joint sketch
  Y=np.eye(16)[yy[tr]]; coef=np.linalg.solve(a@a.T+alpha*np.eye(tr.sum()),Y)
  pred[te]=np.argmax((b@a.T)@coef,axis=1)
 return float(np.mean(pred==yy)),pred
rng=np.random.default_rng(0x4d554c54493444)
res={}
for b,name in [(0,'length_control'),(1,'payload')]:
 ix=np.where((src=='control')&(block==b))[0]; yy=y[ix]; obs,pred=predict(yy,b)
 null=[]
 for k in range(300): null.append(predict(rng.permutation(yy),b)[0])
 null=np.array(null); res[name]={'accuracy':obs,'chance':1/16,'permutation_mean':float(null.mean()),'permutation_p':float((1+np.sum(null>=obs))/(len(null)+1)),'correct':int(np.sum(pred==yy)),'n':len(yy)}
# Mode-flattening spectra: report concentration, not marginals.
def spectral(a):
 t=a.reshape(2,10,10,10); out=[]
 for mode in range(4):
  m=np.moveaxis(t,mode,0).reshape(t.shape[mode],-1); s=np.linalg.svd(m,compute_uv=False);out.append(float((s[0]**2)/(s@s)))
 return out
art=X[src=='artifact']; ctl=X[(src=='control')&(block==1)]
res['mode_top_energy']={'artifact_mean':np.mean([spectral(a) for a in art],0).tolist(),'control_mean':np.mean([spectral(a) for a in ctl],0).tolist(),'artifact_n':len(art),'control_n':len(ctl)}
# Apply payload classifier to artifact only as a falsification diagnostic; without control
# generalization this is explicitly not a plaintext estimate.
ix=np.where((src=='control')&(block==1))[0]; a,b=whiten(X[ix],art); Y=np.eye(16)[y[ix]]; C=np.linalg.solve(a@a.T+100*np.eye(len(ix)),Y); score=(b@a.T)@C
res['artifact_classifier_diagnostic']={'predicted_classes':np.argmax(score,1).tolist(),'mean_softmax_confidence':float(np.mean(np.max(np.exp(score-score.max(1,keepdims=True))/np.exp(score-score.max(1,keepdims=True)).sum(1,keepdims=True),1)))}
print(json.dumps(res,indent=2))
